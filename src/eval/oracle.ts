/**
 * Oracle-based accuracy evaluation harness for HMA NanoMind classifier and ARP engine.
 *
 * Runs the scanner against a directory of hand-labeled oracle fixtures and reports
 * per-surface precision, recall, F1, and a confusion matrix.
 *
 * Usage:
 *   hackmyagent eval oracle --oracle-dir <path> [--format json|text] [--output <file>]
 *
 * See: hackmyagent-redteam-oracle/METHODOLOGY.md for fixture format and release-gate thresholds.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// ── Label taxonomy ─────────────────────────────────────────────────────────

export const GATE_RECALL = 0.85;
export const GATE_PRECISION = 0.90;
export const GATE_F1 = 0.80;

export const ORACLE_LABELS = [
  'benign',
  'injection',
  'exfiltration',
  'credential_abuse',
  'privilege_escalation',
  'persistence',
  'lateral_movement',
  'social_engineering',
  'policy_violation',
  'steganography',
  'tool_poisoning',
  'supply_chain',
  'governance_gap',
  'scope_mismatch',
] as const;

export type OracleLabel = typeof ORACLE_LABELS[number];

export type OracleSurface =
  | 'skill'
  | 'soul'
  | 'mcp'
  | 'arp-input'
  | 'training-sample'
  | 'veil-payload'
  | 'aiis-signature';

// ── Schema types ────────────────────────────────────────────────────────────

export interface OracleFixtureLabel {
  surface: OracleSurface;
  expectedLabel: OracleLabel;
  expectedSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none';
  attackFamily: string;
  expectedChecks: string[];
  hardNegative?: boolean;
  notes?: string;
  author: 'human' | 'human-with-claude-content';
  authoredAt: string;
  retired?: boolean;
  retiredReason?: string;
}

// ── HMA scan result types (matches --format json output) ───────────────────

export interface HmaFinding {
  checkId?: string;
  severity?: string;
  attackClass?: string | null;
  passed?: boolean;
  category?: string;
}

interface HmaScanOutput {
  findings?: HmaFinding[];
  score?: number;
}

// ── Per-fixture evaluation result ───────────────────────────────────────────

export interface FixtureResult {
  fixturePath: string;
  surface: OracleSurface;
  attackFamily: string;
  hardNegative: boolean;
  expectedLabel: OracleLabel;
  expectedSeverity: string;
  expectedChecks: string[];
  predictedLabel: OracleLabel;
  predictedSeverity: string;
  firedChecks: string[];
  correct: boolean;
  severityCorrect: boolean;
  missingExpectedChecks: string[];
  scanOutput: HmaFinding[];
  scanError?: string;
}

// ── Eval report ─────────────────────────────────────────────────────────────

export interface SurfaceMetrics {
  surface: OracleSurface | 'all';
  total: number;
  maliciousTotal: number;
  benignTotal: number;
  tp: number;  // malicious correctly detected
  fp: number;  // benign incorrectly flagged
  fn: number;  // malicious missed
  tn: number;  // benign correctly passed
  precision: number;
  recall: number;
  f1: number;
  fpr: number; // false positive rate = FP / (FP + TN)
  criticalMissed: number; // critical-severity fixtures classified as benign
}

export interface OracleEvalReport {
  timestamp: string;
  oracleDir: string;
  totalFixtures: number;
  retired: number;
  byLabel: Record<string, { total: number; correct: number; incorrect: number }>;
  bySurface: Record<string, SurfaceMetrics>;
  overall: SurfaceMetrics;
  misclassified: FixtureResult[];
  all: FixtureResult[];
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1,
};

/**
 * Map an HMA attackClass string to the closest OracleLabel.
 * HMA attackClass values are free-form; we do a best-effort mapping.
 */
function mapAttackClass(attackClass: string | null | undefined): OracleLabel | null {
  if (!attackClass) return null;
  const c = attackClass.toLowerCase();
  if (c.includes('inject') || c.includes('jailbreak') || c.includes('pi') || c.includes('dan')) return 'injection';
  if (c.includes('exfil') || c.includes('exfiltrat') || c.includes('data_leak')) return 'exfiltration';
  if (c.includes('cred') || c.includes('credential') || c.includes('token') || c.includes('key')) return 'credential_abuse';
  if (c.includes('priv') || c.includes('escalat') || c.includes('rce') || c.includes('exec')) return 'privilege_escalation';
  if (c.includes('persist') || c.includes('heartbeat') || c.includes('startup') || c.includes('lifecycle')) return 'persistence';
  if (c.includes('lateral') || c.includes('shadow') || c.includes('impersonat')) return 'lateral_movement';
  if (c.includes('social') || c.includes('clickfix') || c.includes('phish') || c.includes('deceiv')) return 'social_engineering';
  if (c.includes('policy') || c.includes('bypass') || c.includes('override') || c.includes('violat')) return 'policy_violation';
  if (c.includes('steg') || c.includes('unicode') || c.includes('zero.width') || c.includes('hidden')) return 'steganography';
  if (c.includes('supply') || c.includes('typo') || c.includes('chain')) return 'supply_chain';
  if (c.includes('govern') || c.includes('soul') || c.includes('completeness')) return 'governance_gap';
  if (c.includes('scope') || c.includes('mismatch') || c.includes('undeclared')) return 'scope_mismatch';
  if (c.includes('tool') && c.includes('poison')) return 'tool_poisoning';
  return null;
}

/**
 * Derive a predicted label + severity from HMA JSON output.
 * Strategy: pick the finding with the highest severity that has an attackClass.
 * Fall back to highest severity finding with any category signal.
 * If no malicious findings → benign.
 */
export function derivePrediction(findings: HmaFinding[]): { label: OracleLabel; severity: string; firedChecks: string[] } {
  const firedChecks = findings
    .filter(f => f.passed === false && f.checkId)
    .map(f => f.checkId as string);

  const malicious = findings.filter(f => f.passed === false);
  if (malicious.length === 0) {
    return { label: 'benign', severity: 'none', firedChecks };
  }

  // Sort by severity descending
  const sorted = [...malicious].sort(
    (a, b) => (SEVERITY_RANK[b.severity ?? 'low'] ?? 0) - (SEVERITY_RANK[a.severity ?? 'low'] ?? 0)
  );

  // First try: a finding with an attackClass mapping
  for (const f of sorted) {
    const mapped = mapAttackClass(f.attackClass);
    if (mapped) {
      return { label: mapped, severity: f.severity ?? 'medium', firedChecks };
    }
  }

  // Second try: infer from category
  const top = sorted[0];
  const cat = (top.category ?? '').toLowerCase();
  let label: OracleLabel;
  if (cat === 'skill') label = 'injection';         // default skill malicious
  else if (cat === 'soul') label = 'governance_gap';
  else if (cat === 'mcp') label = 'scope_mismatch';
  else if (cat === 'cred') label = 'credential_abuse';
  else if (cat === 'network') label = 'exfiltration';
  else label = 'injection'; // safest default: something was found

  return { label, severity: top.severity ?? 'medium', firedChecks };
}

/**
 * Run the HMA scanner against a fixture directory and return parsed JSON findings.
 */
function runHmaScanner(fixtureDir: string): { findings: HmaFinding[]; error?: string } {
  // Find the hackmyagent binary — prefer local node_modules, fall back to PATH
  const binPath = path.resolve(__dirname, '../../node_modules/.bin/hackmyagent');
  const bin = fs.existsSync(binPath) ? binPath : 'hackmyagent';

  const result = spawnSync(bin, ['secure', fixtureDir, '--format', 'json', '--static-only'], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 10 * 1024 * 1024,
  });

  if (result.error) {
    return { findings: [], error: result.error.message };
  }

  const raw = result.stdout?.trim() ?? '';
  if (!raw) {
    return { findings: [], error: result.stderr?.trim() || 'No output from scanner' };
  }

  try {
    const parsed = JSON.parse(raw) as HmaScanOutput | HmaFinding[];
    if (Array.isArray(parsed)) return { findings: parsed };
    if (parsed.findings) return { findings: parsed.findings };
    return { findings: [] };
  } catch {
    // Scanner may print human-readable with JSON embedded — try to extract
    const match = raw.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
    if (match) {
      try {
        const parsed = JSON.parse(match[1]) as HmaScanOutput | HmaFinding[];
        if (Array.isArray(parsed)) return { findings: parsed };
        if ((parsed as HmaScanOutput).findings) return { findings: (parsed as HmaScanOutput).findings! };
      } catch { /* fall through */ }
    }
    return { findings: [], error: `Parse error: ${raw.slice(0, 200)}` };
  }
}

/**
 * Run ARP pattern engine against a raw text input.
 */
async function runArpScanner(inputText: string): Promise<{ findings: HmaFinding[]; error?: string }> {
  try {
    const { scanText, ALL_PATTERNS } = await import('../arp/patterns/ai-threats.js');
    const result = scanText(inputText, ALL_PATTERNS);
    const findings: HmaFinding[] = result.matches.map(m => ({
      checkId: `ARP-${m.pattern.id ?? m.pattern.category}`,
      severity: m.pattern.severity ?? 'high',
      attackClass: m.pattern.category ?? null,
      passed: false,
      category: 'arp',
    }));
    return { findings };
  } catch (err) {
    return { findings: [], error: `ARP import failed: ${String(err)}` };
  }
}

// ── Metrics computation ──────────────────────────────────────────────────────

export function computeMetrics(subset: FixtureResult[], surfaceName: OracleSurface | 'all'): SurfaceMetrics {
  let tp = 0, fp = 0, fn = 0, tn = 0, criticalMissed = 0;
  for (const r of subset) {
    const isMaliciousExpected = r.expectedLabel !== 'benign';
    const isMaliciousPredicted = r.predictedLabel !== 'benign';
    if (isMaliciousExpected && isMaliciousPredicted) tp++;
    else if (!isMaliciousExpected && isMaliciousPredicted) fp++;
    else if (isMaliciousExpected && !isMaliciousPredicted) {
      fn++;
      if (r.expectedSeverity === 'critical') criticalMissed++;
    }
    else tn++;
  }
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
  const fpr = fp + tn === 0 ? 0 : fp / (fp + tn);
  return {
    surface: surfaceName,
    total: subset.length,
    maliciousTotal: subset.filter(r => r.expectedLabel !== 'benign').length,
    benignTotal: subset.filter(r => r.expectedLabel === 'benign').length,
    tp, fp, fn, tn,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1: Math.round(f1 * 1000) / 1000,
    fpr: Math.round(fpr * 1000) / 1000,
    criticalMissed,
  };
}

// ── Main eval entry point ────────────────────────────────────────────────────

export async function runOracleEval(oracleDir: string): Promise<OracleEvalReport> {
  const allFixtureLabels: Array<{ dir: string; label: OracleFixtureLabel }> = [];
  const retiredCount = { count: 0 };

  // Walk oracle dir: any subdir containing label.json is a fixture
  function walkDir(dir: string): void {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const fullPath = path.join(dir, entry.name);
      const labelPath = path.join(fullPath, 'label.json');
      if (fs.existsSync(labelPath)) {
        try {
          const raw = fs.readFileSync(labelPath, 'utf8');
          const label = JSON.parse(raw) as OracleFixtureLabel;
          if (label.retired) {
            retiredCount.count++;
          } else {
            allFixtureLabels.push({ dir: fullPath, label });
          }
        } catch (e) {
          // Skip malformed label.json but log
          process.stderr.write(`warn: could not parse ${labelPath}: ${e}\n`);
        }
      } else {
        // Recurse for nested structures (e.g. soul08-skill-conflict has sub-skill)
        walkDir(fullPath);
      }
    }
  }
  walkDir(oracleDir);

  // Evaluate each fixture
  const results: FixtureResult[] = [];
  for (const { dir, label } of allFixtureLabels) {
    let findings: HmaFinding[] = [];
    let scanError: string | undefined;

    if (label.surface === 'arp-input') {
      const inputPath = path.join(dir, 'input.txt');
      if (fs.existsSync(inputPath)) {
        const text = fs.readFileSync(inputPath, 'utf8');
        const r = await runArpScanner(text);
        findings = r.findings;
        scanError = r.error;
      } else {
        scanError = 'input.txt not found';
      }
    } else {
      // skill, soul, mcp — run static scanner
      const r = runHmaScanner(dir);
      findings = r.findings;
      scanError = r.error;
    }

    const { label: predictedLabel, severity: predictedSeverity, firedChecks } = derivePrediction(findings);
    const correct = predictedLabel === label.expectedLabel;
    const severityCorrect =
      label.expectedSeverity === 'none'
        ? predictedSeverity === 'none'
        : SEVERITY_RANK[predictedSeverity] >= SEVERITY_RANK[label.expectedSeverity] - 1; // within 1 tier

    const missingExpectedChecks = label.expectedChecks.filter(c => !firedChecks.includes(c));

    results.push({
      fixturePath: dir,
      surface: label.surface,
      attackFamily: label.attackFamily,
      hardNegative: label.hardNegative ?? false,
      expectedLabel: label.expectedLabel,
      expectedSeverity: label.expectedSeverity,
      expectedChecks: label.expectedChecks,
      predictedLabel,
      predictedSeverity,
      firedChecks,
      correct,
      severityCorrect,
      missingExpectedChecks,
      scanOutput: findings,
      scanError,
    });
  }

  const surfaces: OracleSurface[] = ['skill', 'soul', 'mcp', 'arp-input'];
  const bySurface: Record<string, SurfaceMetrics> = {};
  for (const s of surfaces) {
    const subset = results.filter(r => r.surface === s);
    if (subset.length > 0) bySurface[s] = computeMetrics(subset, s);
  }
  const overall = computeMetrics(results, 'all');

  // Per-label breakdown
  const byLabel: Record<string, { total: number; correct: number; incorrect: number }> = {};
  for (const r of results) {
    const key = r.expectedLabel;
    if (!byLabel[key]) byLabel[key] = { total: 0, correct: 0, incorrect: 0 };
    byLabel[key].total++;
    if (r.correct) byLabel[key].correct++;
    else byLabel[key].incorrect++;
  }

  const misclassified = results.filter(r => !r.correct);

  return {
    timestamp: new Date().toISOString(),
    oracleDir,
    totalFixtures: results.length,
    retired: retiredCount.count,
    byLabel,
    bySurface,
    overall,
    misclassified,
    all: results,
  };
}

// ── Text report printer ──────────────────────────────────────────────────────

export function printOracleReport(report: OracleEvalReport): void {
  const PASS = '\x1b[32m';
  const FAIL = '\x1b[31m';
  const WARN = '\x1b[33m';
  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';
  const DIM = '\x1b[2m';

  function fmt(n: number, decimals = 3): string {
    return (n * 100).toFixed(1) + '%';
  }

  function passGate(val: number, gate: number): string {
    return val >= gate ? `${PASS}${fmt(val)}${RESET}` : `${FAIL}${fmt(val)} < ${fmt(gate)}${RESET}`;
  }

  console.log('');
  console.log(`${BOLD}HMA Oracle Accuracy Eval${RESET}`);
  console.log(`${DIM}${report.timestamp}${RESET}`);
  console.log(`Fixtures: ${report.totalFixtures} evaluated, ${report.retired} retired`);
  console.log('');

  // Per-surface table
  console.log(`${BOLD}Per-Surface Results${RESET}`);
  console.log('─'.repeat(72));
  console.log(
    `${'Surface'.padEnd(14)} ${'Total'.padStart(5)} ${'Mal'.padStart(4)} ${'Ben'.padStart(4)} ${'Prec'.padStart(7)} ${'Recall'.padStart(7)} ${'F1'.padStart(7)} ${'FPR'.padStart(7)} ${'Crit?'.padStart(6)}`
  );
  console.log('─'.repeat(72));

  const gateRecall = GATE_RECALL;
  const gatePrecision = GATE_PRECISION;

  for (const [surface, m] of Object.entries(report.bySurface)) {
    const critWarn = m.criticalMissed > 0 ? `${FAIL}${m.criticalMissed} missed${RESET}` : `${PASS}ok${RESET}`;
    console.log(
      `${surface.padEnd(14)} ${String(m.total).padStart(5)} ${String(m.maliciousTotal).padStart(4)} ${String(m.benignTotal).padStart(4)} ${passGate(m.precision, gatePrecision).padStart(16)} ${passGate(m.recall, gateRecall).padStart(16)} ${fmt(m.f1).padStart(7)} ${fmt(m.fpr).padStart(7)} ${critWarn}`
    );
  }
  console.log('─'.repeat(72));
  const o = report.overall;
  const critWarn = o.criticalMissed > 0 ? `${FAIL}${o.criticalMissed} missed${RESET}` : `${PASS}ok${RESET}`;
  console.log(
    `${'OVERALL'.padEnd(14)} ${String(o.total).padStart(5)} ${String(o.maliciousTotal).padStart(4)} ${String(o.benignTotal).padStart(4)} ${passGate(o.precision, gatePrecision).padStart(16)} ${passGate(o.recall, gateRecall).padStart(16)} ${fmt(o.f1).padStart(7)} ${fmt(o.fpr).padStart(7)} ${critWarn}`
  );
  console.log('');

  // Release gate verdict
  const gatePass =
    o.recall >= gateRecall &&
    o.precision >= gatePrecision &&
    o.f1 >= GATE_F1 &&
    o.criticalMissed === 0 &&
    Object.values(report.bySurface).every(m => m.recall >= gateRecall && m.precision >= gatePrecision);

  if (gatePass) {
    console.log(`${BOLD}${PASS}RELEASE GATE: PASS${RESET}`);
  } else {
    console.log(`${BOLD}${FAIL}RELEASE GATE: FAIL${RESET}`);
    if (o.recall < gateRecall) console.log(`  ${FAIL}Overall recall ${fmt(o.recall)} < gate ${fmt(gateRecall)}${RESET}`);
    if (o.precision < gatePrecision) console.log(`  ${FAIL}Overall precision ${fmt(o.precision)} < gate ${fmt(gatePrecision)}${RESET}`);
    if (o.f1 < GATE_F1) console.log(`  ${FAIL}Overall F1 ${fmt(o.f1)} < gate ${fmt(GATE_F1)}${RESET}`);
    if (o.criticalMissed > 0) console.log(`  ${FAIL}${o.criticalMissed} critical fixtures classified as benign${RESET}`);
    for (const [surface, m] of Object.entries(report.bySurface)) {
      if (m.recall < gateRecall) console.log(`  ${FAIL}${surface} recall ${fmt(m.recall)} < gate${RESET}`);
      if (m.precision < gatePrecision) console.log(`  ${FAIL}${surface} precision ${fmt(m.precision)} < gate${RESET}`);
    }
  }
  console.log('');

  // Per-label accuracy
  console.log(`${BOLD}Per-Label Accuracy${RESET}`);
  console.log('─'.repeat(40));
  for (const [label, stats] of Object.entries(report.byLabel).sort((a, b) => a[0].localeCompare(b[0]))) {
    const acc = stats.total === 0 ? 0 : stats.correct / stats.total;
    const bar = acc >= 0.8 ? PASS : acc >= 0.5 ? WARN : FAIL;
    console.log(`  ${label.padEnd(22)} ${bar}${String(stats.correct).padStart(3)}/${stats.total}  (${fmt(acc)})${RESET}`);
  }
  console.log('');

  // Misclassified
  if (report.misclassified.length === 0) {
    console.log(`${PASS}All fixtures classified correctly.${RESET}`);
  } else {
    console.log(`${BOLD}Misclassified Fixtures (${report.misclassified.length})${RESET}`);
    console.log('─'.repeat(72));
    for (const r of report.misclassified) {
      const fixtureName = path.basename(r.fixturePath);
      const hardFlag = r.hardNegative ? ` ${WARN}[hard-neg]${RESET}` : '';
      console.log(`  ${FAIL}${fixtureName}${RESET}${hardFlag}`);
      console.log(`    surface:  ${r.surface}`);
      console.log(`    expected: ${r.expectedLabel} (${r.expectedSeverity})`);
      console.log(`    got:      ${r.predictedLabel} (${r.predictedSeverity})`);
      if (r.missingExpectedChecks.length > 0) {
        console.log(`    missing checks: ${r.missingExpectedChecks.join(', ')}`);
      }
      if (r.scanError) console.log(`    ${WARN}scan error: ${r.scanError}${RESET}`);
      console.log('');
    }
  }
}
