#!/usr/bin/env node
/**
 * HackMyAgent CLI
 * Find it. Break it. Fix it.
 */

import { Command } from 'commander';
import {
  VERSION,
  checkSkill,
  HardeningScanner,
  ExternalScanner,
  type RiskLevel,
  type Severity,
  type SecurityFinding,
  type ExternalFinding,
  type FindingSeverity,
  // Benchmark imports
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  getCheckIdsForLevel,
  calculateRating,
  AVAILABLE_BENCHMARKS,
  isValidBenchmark,
  type BenchmarkLevel,
  type BenchmarkControl,
  type BenchmarkCategory,
  type BenchmarkResult,
  type BenchmarkCategoryResult,
  type BenchmarkControlResult,
  // Attack imports
  AttackScanner,
  ATTACK_CATEGORIES,
  PAYLOAD_STATS,
  parseCustomPayloads,
  shouldFail,
  type AttackCategory,
  type AttackIntensity,
  type AttackTarget,
  type AttackReport,
  type AttackPayload,
  type FailPolicy,
  // Soul scanner imports
  SoulScanner,
  type SoulScanResult,
  type DomainResult,
  type SoulLevel,
} from './index';
import { resolveAndLogMcpShorthand } from './resolve-mcp';
import { NemoClawScanner, NEMOCLAW_CATEGORIES } from './hardening/nemoclaw-scanner';

const program = new Command();
program.showHelpAfterError('(run with --help for usage)');

// Write JSON to stdout synchronously with retry for pipe backpressure.
// process.stdout.write() is async and gets truncated when process.exit()
// runs before the stream flushes. fs.writeFileSync(1, ...) can fail with
// EAGAIN on non-blocking pipes when the buffer (64KB on macOS) fills up.
// This function writes in chunks with retry to handle both cases.
function writeJsonStdout(data: unknown): void {
  const fs = require('fs');
  const buf = Buffer.from(JSON.stringify(data, null, 2) + '\n');
  let offset = 0;
  while (offset < buf.length) {
    try {
      const written = fs.writeSync(1, buf, offset, buf.length - offset);
      offset += written;
    } catch (e: unknown) {
      if (e && typeof e === 'object' && 'code' in e && (e as {code: string}).code === 'EAGAIN') {
        // Pipe buffer full — spin-wait briefly then retry
        continue;
      }
      throw e;
    }
  }
}

// Resolve the CLI command name based on how we were invoked.
// When run via `opena2a scan secure`, use `opena2a scan` prefix.
// When run directly as `hackmyagent`, use that.
// The HMA_CLI_PREFIX env var lets parent CLIs override explicitly.
function resolveCliPrefix(): string {
  if (process.env.HMA_CLI_PREFIX) return process.env.HMA_CLI_PREFIX;
  const argv1 = process.argv[1] || '';
  const basename = require('path').basename(argv1).replace(/\.[jt]s$/, '');
  if (basename === 'opena2a' || basename.startsWith('opena2a-')) {
    return 'opena2a scan';
  }
  return 'hackmyagent';
}
const CLI_PREFIX = resolveCliPrefix();

// Check for NO_COLOR env or non-TTY to disable colors by default
const noColorEnv = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;

// Color codes - will be cleared if --no-color is passed
let colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  brightRed: '\x1b[91m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
};

if (noColorEnv) {
  colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', dim: '', reset: '' };
}

// Deprecation warning for removed HMAC auth
if (process.env.HMA_COMMUNITY_SECRET) {
  console.error('Note: HMA_COMMUNITY_SECRET is deprecated and no longer used. Scan tokens are now issued automatically.');
}

program
  .name('hackmyagent')
  .description(`Find it. Break it. Fix it.

The hacker's toolkit for AI agents. 202 security checks, 115 attack
payloads, auto-fix with rollback, and OASB benchmark compliance.

Documentation: https://hackmyagent.com/docs

Updates (v${VERSION}):
  - NemoClaw sandbox scanner (28 installation checks)
  - 10 new static analysis patterns (NEMO series)
  - Community trust contributions
  - 202 checks across 39 categories

Examples:
  $ hackmyagent secure                         Find vulnerabilities (202 checks)
  $ hackmyagent attack --local                 Break it with 115 attack payloads
  $ hackmyagent secure --fix                   Fix issues automatically
  $ hackmyagent fix-all                        Run all security plugins
  $ hackmyagent scan example.com               Scan external infrastructure`)
  .version('hackmyagent ' + VERSION, '-v, --version', 'Output the version number')
  .option('--no-color', 'Disable colored output (also respects NO_COLOR env)');

program.addHelpText('beforeAll', `
Quick start:
  $ hackmyagent secure              Scan current directory (202 checks)
  $ hackmyagent fix-all --with-aim  Auto-fix + create agent identity
  $ hackmyagent attack              Red-team your agent
`);

program.hook('preAction', (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.color === false) {
      colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', dim: '', reset: '' };
    }
  });

// Risk level colors and symbols
const RISK_DISPLAY: Record<RiskLevel, { symbol: string; color: () => string }> = {
  low: { symbol: '[+]', color: () => colors.green },
  medium: { symbol: '[~]', color: () => colors.yellow },
  high: { symbol: '[!]', color: () => colors.red },
  critical: { symbol: '[!!]', color: () => colors.brightRed },
};
const RESET = () => colors.reset;

program
  .command('check')
  .description(`Verify a skill before installing

Analyzes skill safety by checking:
  • Publisher identity via DNS TXT records
  • Permissions requested (filesystem, network, shell)
  • Revocation status against global blocklist

Risk levels: low, medium, high, critical
Exit code 1 if high/critical risk detected.

Examples:
  $ hackmyagent check @anthropic/claude-mcp
  $ hackmyagent check @publisher/skill --verbose
  $ hackmyagent check @publisher/skill --json`)
  .argument('<skill>', 'Skill identifier (e.g., @publisher/skill)')
  .option('-v, --verbose', 'Show detailed verification info')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('--offline', 'Skip DNS verification (offline mode)')
  .action(async (skill: string, options: { verbose?: boolean; json?: boolean; offline?: boolean }) => {
    try {
      const result = await checkSkill(skill, {
        skipDnsVerification: options.offline,
      });

      if (options.json) {
        writeJsonStdout(result);
        return;
      }

      const risk = RISK_DISPLAY[result.risk];
      console.log(`\n${risk.color()}${risk.symbol} ${result.risk.toUpperCase()} RISK${RESET()}\n`);

      // Publisher info
      console.log(`Publisher: @${result.publisher.name}`);
      if (result.publisher.verified) {
        console.log(`├─ [+] Verified via DNS`);
        if (result.publisher.domain) {
          console.log(`├─ Domain: ${result.publisher.domain}`);
        }
        if (result.publisher.verifiedAt && options.verbose) {
          console.log(`└─ Verified at: ${result.publisher.verifiedAt.toISOString()}`);
        } else {
          console.log(`└─ Method: DNS TXT record`);
        }
      } else {
        console.log(`├─ [-] Not verified`);
        if (result.publisher.failureReason && options.verbose) {
          console.log(`└─ Reason: ${result.publisher.failureReason}`);
        } else if (options.offline) {
          console.log(`└─ (DNS verification skipped - offline mode)`);
        } else {
          console.log(`└─ No valid DNS TXT record found`);
        }
      }
      console.log();

      // Permissions
      console.log('Permissions:');
      if (result.permissions.requested.length === 0) {
        console.log('└─ None declared');
      } else {
        for (const perm of result.permissions.safe) {
          console.log(`├─ [+] ${perm}`);
        }
        for (const perm of result.permissions.reviewNeeded) {
          console.log(`├─ [~] ${perm} (review needed)`);
        }
        for (const perm of result.permissions.dangerous) {
          console.log(`├─ [!] ${perm} (elevated risk)`);
        }
        console.log(`└─ Risk score: ${result.permissions.riskScore}/100`);
      }
      console.log();

      // Revocation
      console.log('Revocation:');
      if (result.revocation.revoked) {
        console.log(`└─ [!!] Revoked: ${result.revocation.reason}`);
      } else {
        console.log(`└─ [+] Not on blocklist`);
      }
      console.log();

      // Verbose details
      if (options.verbose) {
        console.log('Details:');
        console.log(`└─ Checked at: ${result.revocation.checkedAt.toISOString()}`);
      }

      // Exit with non-zero for high/critical risk
      if (result.risk === 'critical' || result.risk === 'high') {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Severity colors and symbols for secure command
const SEVERITY_DISPLAY: Record<Severity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
};

function groupFindingsBySeverity(findings: SecurityFinding[]): Record<Severity, SecurityFinding[]> {
  const grouped: Record<Severity, SecurityFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

// Benchmark compliance helpers
interface LocalControlResult {
  control: BenchmarkControl;
  status: 'passed' | 'failed' | 'unverified';
  findings: string[];
  remediation?: string;
}

function generateBenchmarkReport(
  findings: SecurityFinding[],
  level: BenchmarkLevel,
  categoryFilter?: string
): BenchmarkResult {
  // Get controls for the specified level
  let controls = getControlsForLevel(level);

  // Filter by category if specified
  if (categoryFilter) {
    const categoryControls = getControlsForCategory(categoryFilter);
    if (categoryControls.length === 0) {
      console.error(`Error: Unknown category '${categoryFilter}'.`);
      console.error(`Available categories: ${OASB_1_CATEGORIES.map((c: BenchmarkCategory) => c.name).join(', ')}`);
      process.exit(1);
    }
    controls = controls.filter((c: BenchmarkControl) => c.category.toLowerCase() === categoryFilter.toLowerCase());
  }

  // Build a map of checkId -> finding for quick lookup
  const findingsByCheckId = new Map<string, SecurityFinding>();
  for (const finding of findings) {
    findingsByCheckId.set(finding.checkId, finding);
  }

  // Evaluate each control
  const controlResults: LocalControlResult[] = [];
  let l1Passed = 0, l1Total = 0;
  let l2Passed = 0, l2Total = 0;
  let l3Passed = 0, l3Total = 0;
  let passedCount = 0, failedCount = 0, unverifiedCount = 0;

  for (const control of controls) {
    let status: 'passed' | 'failed' | 'unverified';
    const relatedFindings: string[] = [];
    let remediation: string | undefined;

    if (control.verification === 'manual' || control.verification === 'forward') {
      // Manual/forward controls are unverified (human must check)
      status = 'unverified';
      unverifiedCount++;
      // Use control's remediation for manual/forward controls
      remediation = control.remediation;
    } else if (control.checkIds.length === 0) {
      // No automated checks defined
      status = 'unverified';
      unverifiedCount++;
      remediation = control.remediation;
    } else {
      // Check all mapped check IDs
      let hasAnyFinding = false;
      let hasFailure = false;
      for (const checkId of control.checkIds) {
        const finding = findingsByCheckId.get(checkId);
        if (finding) {
          hasAnyFinding = true;
          if (!finding.passed) {
            hasFailure = true;
            relatedFindings.push(`${checkId}: ${finding.description}`);
            if (finding.fix) {
              remediation = remediation || finding.fix;
            }
          }
        }
      }
      // Only mark as passed if we actually verified something
      // Missing findings = unverified (not passed)
      if (!hasAnyFinding) {
        status = 'unverified';
        unverifiedCount++;
        remediation = control.remediation;
      } else if (hasFailure) {
        status = 'failed';
        failedCount++;
        remediation = remediation || control.remediation;
      } else {
        status = 'passed';
        passedCount++;
      }
    }

    // Count by level for compliance calculation
    if (control.scored && status !== 'unverified') {
      if (control.level === 'L1') {
        l1Total++;
        if (status === 'passed') l1Passed++;
      } else if (control.level === 'L2') {
        l2Total++;
        if (status === 'passed') l2Passed++;
      } else if (control.level === 'L3') {
        l3Total++;
        if (status === 'passed') l3Passed++;
      }
    }

    controlResults.push({ control, status, findings: relatedFindings, remediation });
  }

  // Calculate compliance percentages
  const l1Compliance = l1Total > 0 ? Math.round((l1Passed / l1Total) * 100) : 100;
  const l2Compliance = l2Total > 0 ? Math.round((l2Passed / l2Total) * 100) : 100;
  const l3Compliance = l3Total > 0 ? Math.round((l3Passed / l3Total) * 100) : 100;
  const totalScored = l1Total + l2Total + l3Total;
  const totalPassed = l1Passed + l2Passed + l3Passed;
  const overallCompliance = totalScored > 0 ? Math.round((totalPassed / totalScored) * 100) : 0;

  // Group results by category
  const categoryResults: BenchmarkCategoryResult[] = [];
  for (const category of OASB_1_CATEGORIES) {
    if (categoryFilter && category.name.toLowerCase() !== categoryFilter.toLowerCase()) continue;

    const catControls = controlResults.filter((r: LocalControlResult) => r.control.category === category.name);
    if (catControls.length === 0) continue;

    const passed = catControls.filter((r: LocalControlResult) => r.status === 'passed').length;
    const failed = catControls.filter((r: LocalControlResult) => r.status === 'failed').length;
    const unverified = catControls.filter((r: LocalControlResult) => r.status === 'unverified').length;
    const compliance = (passed + failed) > 0 ? Math.round((passed / (passed + failed)) * 100) : 0;

    categoryResults.push({
      category: category.name,
      compliance,
      passed,
      failed,
      unverified,
      controls: catControls.map((r: LocalControlResult) => ({
        controlId: r.control.id,
        name: r.control.name,
        level: r.control.level,
        status: r.status,
        findings: r.findings,
        remediation: r.remediation,
      })),
    });
  }

  const rating = calculateRating(l1Compliance, l2Compliance, l3Compliance, level);

  return {
    benchmark: OASB_1_NAME,
    version: OASB_1_VERSION,
    level,
    timestamp: new Date(),
    compliance: overallCompliance,
    l1Compliance,
    l2Compliance,
    l3Compliance,
    rating,
    categories: categoryResults,
    totalControls: controls.length,
    passedControls: passedCount,
    failedControls: failedCount,
    unverifiedControls: unverifiedCount,
  };
}

// SARIF 2.1.0 output for GitHub Security tab and IDE integration
function generateSarifOutput(benchmarkResult: BenchmarkResult, findings: SecurityFinding[], targetDir: string): string {
  const rules: Array<{
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string; markdown?: string };
    helpUri?: string;
    defaultConfiguration: { level: 'error' | 'warning' | 'note' };
    properties: { 'security-severity': string; tags: string[] };
  }> = [];

  const results: Array<{
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: { text: string };
    locations?: Array<{
      physicalLocation: {
        artifactLocation: { uri: string };
        region?: { startLine: number; endLine?: number };
      };
    }>;
  }> = [];

  // Build rules and results from benchmark controls
  for (const cat of benchmarkResult.categories) {
    for (const ctrl of cat.controls) {
      if (ctrl.status === 'failed') {
        const ruleId = `OASB-1/${ctrl.controlId}`;
        const severityScore = ctrl.level === 'L1' ? '8.0' : ctrl.level === 'L2' ? '6.0' : '4.0';
        const sarifLevel: 'error' | 'warning' | 'note' = ctrl.level === 'L1' ? 'error' : ctrl.level === 'L2' ? 'warning' : 'note';

        rules.push({
          id: ruleId,
          name: ctrl.name.replace(/\s+/g, ''),
          shortDescription: { text: ctrl.name },
          fullDescription: { text: `OASB-1 ${ctrl.level} Control: ${ctrl.name}` },
          help: {
            text: ctrl.remediation || `Fix the ${ctrl.name} control to achieve compliance.`,
            markdown: ctrl.remediation ? `**Remediation:** ${ctrl.remediation}` : undefined,
          },
          helpUri: `https://oasb.ai/controls/${ctrl.controlId}`,
          defaultConfiguration: { level: sarifLevel },
          properties: {
            'security-severity': severityScore,
            tags: ['security', 'oasb-1', ctrl.level.toLowerCase()],
          },
        });

        // Find related findings for locations
        const relatedFindings = findings.filter(f => ctrl.findings.some(cf => cf.includes(f.checkId)));

        if (relatedFindings.length > 0) {
          for (const finding of relatedFindings) {
            results.push({
              ruleId,
              level: sarifLevel,
              message: { text: finding.description },
              locations: finding.file ? [{
                physicalLocation: {
                  artifactLocation: { uri: finding.file.replace(targetDir + '/', '') },
                  region: finding.line ? { startLine: finding.line } : undefined,
                },
              }] : undefined,
            });
          }
        } else {
          // No specific location, just report the control failure
          results.push({
            ruleId,
            level: sarifLevel,
            message: { text: ctrl.findings.join('; ') || `Control ${ctrl.controlId} failed` },
          });
        }
      }
    }
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0' as const,
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// HTML report for shareable compliance documentation
function generateHtmlReport(result: BenchmarkResult): string {
  const ratingColor = {
    'Certified': '#22c55e',
    'Compliant': '#22c55e',
    'Passing': '#eab308',
    'Needs Improvement': '#f97316',
    'Not Passing': '#ef4444',
  }[result.rating] || '#94a3b8';

  const ratingBg = {
    'Certified': 'rgba(34, 197, 94, 0.15)',
    'Compliant': 'rgba(34, 197, 94, 0.15)',
    'Passing': 'rgba(234, 179, 8, 0.15)',
    'Needs Improvement': 'rgba(249, 115, 22, 0.15)',
    'Not Passing': 'rgba(239, 68, 68, 0.15)',
  }[result.rating] || 'rgba(148, 163, 184, 0.15)';

  // Generate donut chart SVG
  const donutRadius = 70;
  const donutStroke = 14;
  const donutCircumference = 2 * Math.PI * donutRadius;
  const donutOffset = donutCircumference * (1 - result.compliance / 100);
  const complianceColor = result.compliance >= 90 ? '#22c55e' : result.compliance >= 70 ? '#eab308' : '#ef4444';

  // Generate radar chart data points
  const radarCategories = result.categories.slice(0, 10); // Max 10 for radar
  const radarPoints: string[] = [];
  const radarLabels: string[] = [];
  const radarCenter = 120;
  const radarRadius = 90;

  // Category name abbreviations for radar chart labels
  const categoryAbbreviations: Record<string, string> = {
    'Identity & Provenance': 'Identity',
    'Capability & Authorization': 'Capability',
    'Input Security': 'Input',
    'Output Security': 'Output',
    'Credential Protection': 'Credentials',
    'Supply Chain Integrity': 'Supply Chain',
    'Agent-to-Agent Security': 'A2A Security',
    'Memory & Context Integrity': 'Memory',
    'Operational Security': 'Operations',
    'Monitoring & Response': 'Monitoring',
  };

  radarCategories.forEach((cat, i) => {
    const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
    // Use minimum 5% so 0% categories still show on the chart edge (not at center)
    const value = Math.max(0.05, cat.compliance / 100);
    const x = radarCenter + Math.cos(angle) * radarRadius * value;
    const y = radarCenter + Math.sin(angle) * radarRadius * value;
    radarPoints.push(`${x},${y}`);

    // Label position (slightly outside)
    const labelX = radarCenter + Math.cos(angle) * (radarRadius + 20);
    const labelY = radarCenter + Math.sin(angle) * (radarRadius + 20);
    const shortName = categoryAbbreviations[cat.category] || cat.category.split(' ')[0];
    radarLabels.push(`<text x="${labelX}" y="${labelY}" text-anchor="middle" dominant-baseline="middle" fill="#94a3b8" font-size="10" font-weight="500">${escapeHtml(shortName)}</text>`);
  });

  // Generate radar grid lines
  const radarGrid = [0.25, 0.5, 0.75, 1].map(scale => {
    const points = radarCategories.map((_, i) => {
      const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
      const x = radarCenter + Math.cos(angle) * radarRadius * scale;
      const y = radarCenter + Math.sin(angle) * radarRadius * scale;
      return `${x},${y}`;
    }).join(' ');
    return `<polygon points="${points}" fill="none" stroke="#334155" stroke-width="1"/>`;
  }).join('');

  // Radar axis lines
  const radarAxes = radarCategories.map((_, i) => {
    const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
    const x = radarCenter + Math.cos(angle) * radarRadius;
    const y = radarCenter + Math.sin(angle) * radarRadius;
    return `<line x1="${radarCenter}" y1="${radarCenter}" x2="${x}" y2="${y}" stroke="#334155" stroke-width="1"/>`;
  }).join('');

  // Collect all controls for statistics
  const allControls = result.categories.flatMap(cat => cat.controls);
  const failedControls = allControls.filter(ctrl => ctrl.status === 'failed');
  const passedControls = allControls.filter(ctrl => ctrl.status === 'passed');
  const unverifiedControls = allControls.filter(ctrl => ctrl.status === 'unverified');

  // Level breakdown stats
  const levelStats = {
    L1: { passed: 0, failed: 0, total: 0 },
    L2: { passed: 0, failed: 0, total: 0 },
    L3: { passed: 0, failed: 0, total: 0 },
  };
  allControls.forEach(ctrl => {
    const lvl = ctrl.level as 'L1' | 'L2' | 'L3';
    if (levelStats[lvl]) {
      levelStats[lvl].total++;
      if (ctrl.status === 'passed') levelStats[lvl].passed++;
      if (ctrl.status === 'failed') levelStats[lvl].failed++;
    }
  });

  // Find worst category
  const worstCategory = result.categories
    .filter(cat => cat.passed + cat.failed > 0)
    .sort((a, b) => a.compliance - b.compliance)[0];

  // Security grade based on compliance
  const getGrade = (pct: number) => {
    if (pct >= 90) return { letter: 'strong', color: '#22c55e' };
    if (pct >= 80) return { letter: 'good', color: '#84cc16' };
    if (pct >= 70) return { letter: 'moderate', color: '#eab308' };
    if (pct >= 60) return { letter: 'improving', color: '#f97316' };
    return { letter: 'needs-attention', color: '#ef4444' };
  };
  const grade = getGrade(result.compliance);

  // Generate executive summary items
  const executiveSummary = failedControls.length === 0
    ? '<div class="exec-item success"><span class="exec-icon">✓</span><span>All controls passing at this level</span></div>'
    : failedControls.slice(0, 5).map(ctrl =>
        `<div class="exec-item critical"><span class="exec-icon">!</span><span><strong>${ctrl.controlId}</strong>: ${escapeHtml(ctrl.name)}</span></div>`
      ).join('') + (failedControls.length > 5 ? `<div class="exec-item warning"><span class="exec-icon">+</span><span>${failedControls.length - 5} more issues not shown</span></div>` : '');

  // SVG icons for professional look (no emojis)
  const icons = {
    check: '<svg class="icon icon-check" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>',
    x: '<svg class="icon icon-x" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>',
    warning: '<svg class="icon icon-warning" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>',
    circle: '<svg class="icon icon-circle" viewBox="0 0 20 20" fill="currentColor"><circle cx="10" cy="10" r="4"/></svg>',
    shield: '<svg class="icon icon-shield" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clip-rule="evenodd"/></svg>',
    print: '<svg class="icon icon-print" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5 4v3H4a2 2 0 00-2 2v3a2 2 0 002 2h1v2a2 2 0 002 2h6a2 2 0 002-2v-2h1a2 2 0 002-2V9a2 2 0 00-2-2h-1V4a2 2 0 00-2-2H7a2 2 0 00-2 2zm8 0H7v3h6V4zm0 8H7v4h6v-4z" clip-rule="evenodd"/></svg>',
  };

  // Category rows with collapsible sections
  const categoryRows = result.categories.map((cat, catIndex) => {
    const statusIcon = cat.failed === 0 ? icons.check : cat.passed > 0 ? icons.warning : icons.x;
    const statusClass = cat.failed === 0 ? 'status-pass' : cat.passed > 0 ? 'status-warn' : 'status-fail';
    const barColor = cat.compliance >= 90 ? '#22c55e' : cat.compliance >= 70 ? '#eab308' : '#ef4444';

    const controlRows = cat.controls.map(ctrl => {
      const statusSvg = ctrl.status === 'passed' ? icons.check : ctrl.status === 'failed' ? icons.x : icons.circle;
      const ctrlStatusClass = ctrl.status === 'passed' ? 'status-pass' : ctrl.status === 'failed' ? 'status-fail' : 'status-unverified';
      const findingsList = ctrl.findings.length > 0
        ? `<ul class="findings">${ctrl.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>`
        : '';
      const remediation = ctrl.remediation
        ? `<div class="remediation"><strong>Remediation:</strong> ${escapeHtml(ctrl.remediation)}</div>`
        : '';
      return `
        <tr class="control-row ${ctrl.status}">
          <td class="status-cell"><span class="${ctrlStatusClass}">${statusSvg}</span></td>
          <td class="id-cell"><code>${ctrl.controlId}</code></td>
          <td class="name-cell">${escapeHtml(ctrl.name)}</td>
          <td class="level-cell"><span class="level-badge level-${ctrl.level.toLowerCase()}">${ctrl.level}</span></td>
          <td class="details-cell">${findingsList}${remediation}</td>
        </tr>`;
    }).join('');

    return `
      <div class="category" id="cat-${catIndex}">
        <div class="category-header" onclick="toggleCategory(${catIndex})">
          <span class="category-icon ${statusClass}">${statusIcon}</span>
          <span class="category-name">${escapeHtml(cat.category)}</span>
          <div class="category-meta">
            <span class="category-score">${cat.passed}/${cat.passed + cat.failed}</span>
            <div class="mini-bar"><div class="mini-fill" style="width: ${cat.compliance}%; background: ${barColor};"></div></div>
            <span class="category-percent">${cat.compliance}%</span>
            <span class="chevron">▼</span>
          </div>
        </div>
        <div class="category-content">
          <table class="controls-table">
            <thead><tr><th></th><th>Control ID</th><th>Control Name</th><th>Level</th><th>Details</th></tr></thead>
            <tbody>${controlRows}</tbody>
          </table>
        </div>
      </div>`;
  }).join('');

  // Level description
  const levelDesc = {
    'L1': 'Essential baseline security every agent should implement',
    'L2': 'Defense-in-depth for production systems',
    'L3': 'Maximum security for high-risk or regulated environments'
  }[result.level] || '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OASB-1 Compliance Report | ${result.rating}</title>
  <style>
    :root {
      --bg-primary: #0a0f1a;
      --bg-secondary: #111827;
      --bg-tertiary: #1f2937;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border: #334155;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
      font-size: 14px;
    }
    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding: 1.5rem 2rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .header-left h1 {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .header-left .meta { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem; }
    .header-icon { display: inline-flex; margin-right: 0.5rem; }
    .header-icon .icon { width: 24px; height: 24px; color: var(--accent); }
    .header-right { display: flex; align-items: center; gap: 1rem; }
    .rating-badge {
      display: inline-block;
      padding: 0.375rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.875rem;
      background: ${ratingBg};
      color: ${ratingColor};
      border: 1px solid ${ratingColor}40;
    }
    .level-tag {
      display: inline-block;
      padding: 0.375rem 1rem;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 600;
    }

    /* SVG Icons */
    .icon { width: 16px; height: 16px; display: inline-block; vertical-align: middle; }
    .status-pass { color: var(--success); }
    .status-fail { color: var(--danger); }
    .status-warn { color: var(--warning); }
    .status-unverified { color: var(--text-muted); }
    .category-icon { display: flex; align-items: center; }
    .category-icon .icon { width: 18px; height: 18px; }
    .footer-btn .icon { width: 14px; height: 14px; margin-right: 0.375rem; }

    /* Dashboard grid */
    .dashboard {
      display: grid;
      grid-template-columns: 280px 1fr 300px;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 1200px) {
      .dashboard { grid-template-columns: 1fr 1fr; }
      .radar-section { grid-column: span 2; }
    }
    @media (max-width: 768px) {
      .dashboard { grid-template-columns: 1fr; }
      .radar-section { grid-column: span 1; }
    }

    /* Score card - Prowler style */
    .score-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
    }
    .score-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.25rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .score-grade {
      width: 72px;
      height: 72px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; text-align: center; line-height: 1.2; }
    .score-main { flex: 1; }
    .score-pct { font-size: 2rem; font-weight: 700; color: var(--text-primary); line-height: 1; }
    .score-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }

    .score-bars { margin-bottom: 1rem; }
    .score-bar-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }
    .bar-label { width: 50px; font-size: 0.75rem; color: var(--text-secondary); }
    .bar-track { flex: 1; height: 8px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .bar-pass { background: var(--success); }
    .bar-fail { background: var(--danger); }
    .bar-manual { background: var(--text-muted); }
    .bar-count { width: 24px; font-size: 0.8rem; font-weight: 600; text-align: right; color: var(--text-primary); }

    .level-breakdown {
      display: flex;
      gap: 0.75rem;
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border-radius: 8px;
      margin-bottom: 1rem;
    }
    .level-row { display: flex; align-items: center; gap: 0.375rem; }
    .level-stat { font-size: 0.8rem; color: var(--text-secondary); }

    .worst-category {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.625rem 0.75rem;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 6px;
      border-left: 3px solid var(--danger);
    }
    .worst-label { font-size: 0.7rem; color: var(--danger); text-transform: uppercase; font-weight: 600; }
    .worst-name { flex: 1; font-size: 0.8rem; color: var(--text-primary); }
    .worst-pct { font-size: 0.85rem; font-weight: 700; }

    /* Radar chart */
    .radar-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .radar-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .radar-container { display: flex; justify-content: center; }

    /* Executive summary */
    .exec-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .exec-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .exec-item {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.75rem;
      margin-bottom: 0.5rem;
      border-radius: 6px;
      font-size: 0.85rem;
    }
    .exec-item.critical { background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--danger); }
    .exec-item.warning { background: rgba(234, 179, 8, 0.1); border-left: 3px solid var(--warning); }
    .exec-item.success { background: rgba(34, 197, 94, 0.1); border-left: 3px solid var(--success); }
    .exec-icon {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.75rem;
      flex-shrink: 0;
    }
    .exec-item.critical .exec-icon { background: var(--danger); color: white; }
    .exec-item.warning .exec-icon { background: var(--warning); color: black; }
    .exec-item.success .exec-icon { background: var(--success); color: white; }

    /* Categories */
    .categories-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .categories-header h2 { font-size: 1.1rem; }
    .expand-all {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .expand-all:hover { background: var(--border); }

    .category {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 0.75rem;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .category-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.25rem;
      cursor: pointer;
      transition: background 0.15s;
    }
    .category-header:hover { background: var(--bg-tertiary); }
    .category-icon { font-size: 1.1rem; }
    .category-name { flex: 1; font-weight: 500; }
    .category-meta { display: flex; align-items: center; gap: 0.75rem; }
    .category-score { color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; }
    .mini-bar { width: 60px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .mini-fill { height: 100%; border-radius: 3px; }
    .category-percent { color: var(--text-muted); font-size: 0.85rem; width: 40px; text-align: right; }
    .chevron {
      color: var(--text-muted);
      font-size: 0.7rem;
      transition: transform 0.2s;
      margin-left: 0.5rem;
    }
    .category.collapsed .chevron { transform: rotate(-90deg); }
    .category.collapsed .category-content { display: none; }

    .category-content { border-top: 1px solid var(--border); }
    .controls-table { width: 100%; border-collapse: collapse; }
    .controls-table th {
      padding: 0.75rem 1rem;
      text-align: left;
      background: var(--bg-primary);
      color: var(--text-muted);
      font-weight: 500;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .controls-table td {
      padding: 0.875rem 1rem;
      border-top: 1px solid var(--border);
      vertical-align: top;
    }
    .status-cell { width: 40px; text-align: center; }
    .id-cell { width: 100px; }
    .id-cell code {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: var(--accent);
    }
    .name-cell { width: 30%; }
    .level-cell { width: 60px; }
    .details-cell { color: var(--text-secondary); font-size: 0.85rem; }
    .control-row.failed { background: rgba(239, 68, 68, 0.05); }
    .control-row.unverified { opacity: 0.5; }

    .level-badge {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .level-l1 { background: #7c3aed; color: white; }
    .level-l2 { background: #2563eb; color: white; }
    .level-l3 { background: #059669; color: white; }

    .findings {
      margin: 0.25rem 0 0.5rem;
      padding-left: 1.25rem;
      color: #f87171;
      list-style-type: disc;
    }
    .findings li { margin-bottom: 0.25rem; }
    .remediation {
      margin-top: 0.5rem;
      padding: 0.625rem 0.875rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
      font-size: 0.8rem;
      border-left: 3px solid var(--accent);
    }

    /* Footer */
    .footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 2rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .footer a { color: var(--accent); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .footer-actions { display: flex; gap: 1rem; }
    .footer-btn {
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .footer-btn:hover { background: var(--border); }

    /* Print styles */
    @media print {
      body { background: white; color: black; padding: 1rem; }
      .container { max-width: 100%; }
      .header, .donut-card, .radar-section, .exec-section, .category, .footer {
        background: white;
        border: 1px solid #ddd;
        break-inside: avoid;
      }
      .category.collapsed .category-content { display: block !important; }
      .chevron, .expand-all, .footer-actions { display: none; }
      .category-header { cursor: default; }
      .control-row.failed { background: #fff0f0; }
      :root {
        --bg-primary: white;
        --bg-secondary: white;
        --bg-tertiary: #f5f5f5;
        --text-primary: black;
        --text-secondary: #555;
        --text-muted: #888;
        --border: #ddd;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="header-left">
        <h1><span class="header-icon">${icons.shield}</span>${escapeHtml(result.benchmark)}</h1>
        <div class="meta">Version ${result.version} • Generated ${new Date(result.timestamp).toLocaleString()}</div>
      </div>
      <div class="header-right">
        <div class="rating-badge">${result.rating}</div>
        <div class="level-tag">${result.level} — ${result.level === 'L1' ? 'Essential' : result.level === 'L2' ? 'Standard' : 'Hardened'}</div>
      </div>
    </header>

    <div class="dashboard">
      <div class="score-card">
        <div class="score-header">
          <div class="score-grade" style="background: ${grade.color}20; border-color: ${grade.color};">
            <span class="grade-letter" style="color: ${grade.color};">${grade.letter}</span>
          </div>
          <div class="score-main">
            <div class="score-pct">${result.compliance}%</div>
            <div class="score-label">Security Score</div>
          </div>
        </div>

        <div class="score-bars">
          <div class="score-bar-row">
            <span class="bar-label">Passed</span>
            <div class="bar-track">
              <div class="bar-fill bar-pass" style="width: ${allControls.length ? (passedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${passedControls.length}</span>
          </div>
          <div class="score-bar-row">
            <span class="bar-label">Failed</span>
            <div class="bar-track">
              <div class="bar-fill bar-fail" style="width: ${allControls.length ? (failedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${failedControls.length}</span>
          </div>
          <div class="score-bar-row">
            <span class="bar-label">Manual</span>
            <div class="bar-track">
              <div class="bar-fill bar-manual" style="width: ${allControls.length ? (unverifiedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${unverifiedControls.length}</span>
          </div>
        </div>

        <div class="level-breakdown">
          <div class="level-row">
            <span class="level-badge level-l1">L1</span>
            <span class="level-stat">${levelStats.L1.passed}/${levelStats.L1.total}</span>
          </div>
          <div class="level-row">
            <span class="level-badge level-l2">L2</span>
            <span class="level-stat">${levelStats.L2.passed}/${levelStats.L2.total}</span>
          </div>
          <div class="level-row">
            <span class="level-badge level-l3">L3</span>
            <span class="level-stat">${levelStats.L3.passed}/${levelStats.L3.total}</span>
          </div>
        </div>

        ${worstCategory && worstCategory.compliance < 100 ? `
        <div class="worst-category">
          <span class="worst-label">Needs Attention</span>
          <span class="worst-name">${escapeHtml(worstCategory.category)}</span>
          <span class="worst-pct" style="color: ${worstCategory.compliance < 50 ? '#ef4444' : '#eab308'};">${worstCategory.compliance}%</span>
        </div>` : ''}
      </div>

      <div class="radar-section">
        <h3>Category Coverage</h3>
        <div class="radar-container">
          <svg width="240" height="240" viewBox="0 0 240 240">
            ${radarGrid}
            ${radarAxes}
            <polygon points="${radarPoints.join(' ')}" fill="${complianceColor}20" stroke="${complianceColor}" stroke-width="2"/>
            ${radarLabels.join('')}
          </svg>
        </div>
      </div>

      <div class="exec-section">
        <h3>Priority Issues</h3>
        ${executiveSummary}
        ${failedControls.length > 0 ? `<div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--text-muted);">
          ${levelDesc}
        </div>` : ''}
      </div>
    </div>

    <div class="categories-header">
      <h2>Control Details by Category</h2>
      <button class="expand-all" onclick="toggleAll()">Expand All</button>
    </div>

    ${categoryRows}

    <footer class="footer">
      <div>
        Generated by <a href="https://hackmyagent.com">HackMyAgent</a> •
        <a href="https://oasb.ai">OASB-1 Specification</a>
      </div>
      <div class="footer-actions">
        <button class="footer-btn" onclick="window.print()">${icons.print} Print / PDF</button>
      </div>
    </footer>
  </div>

  <script>
    function toggleCategory(index) {
      const cat = document.getElementById('cat-' + index);
      cat.classList.toggle('collapsed');
    }

    function toggleAll() {
      const categories = document.querySelectorAll('.category');
      const btn = document.querySelector('.expand-all');
      const allCollapsed = Array.from(categories).every(c => c.classList.contains('collapsed'));

      categories.forEach(cat => {
        if (allCollapsed) {
          cat.classList.remove('collapsed');
        } else {
          cat.classList.add('collapsed');
        }
      });

      btn.textContent = allCollapsed ? 'Collapse All' : 'Expand All';
    }

    // Start with categories collapsed
    document.querySelectorAll('.category').forEach(cat => cat.classList.add('collapsed'));
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// SARIF output for non-benchmark secure scans
function generateScanSarif(findings: SecurityFinding[], targetDir: string): string {
  const issues = findings.filter(f => !f.passed && !f.fixed);
  const rules = issues.map(f => ({
    id: f.checkId,
    name: f.name.replace(/\s+/g, ''),
    shortDescription: { text: f.name },
    fullDescription: { text: f.description },
    help: { text: f.fix || `Fix the ${f.name} issue.` },
    defaultConfiguration: {
      level: (f.severity === 'critical' || f.severity === 'high' ? 'error' :
             f.severity === 'medium' ? 'warning' : 'note') as 'error' | 'warning' | 'note',
    },
    properties: {
      'security-severity': f.severity === 'critical' ? '9.0' :
                          f.severity === 'high' ? '7.0' :
                          f.severity === 'medium' ? '5.0' : '3.0',
      tags: ['security', 'ai-agent', f.category],
    },
  }));

  const results = issues.map(f => ({
    ruleId: f.checkId,
    level: (f.severity === 'critical' || f.severity === 'high' ? 'error' :
           f.severity === 'medium' ? 'warning' : 'note') as 'error' | 'warning' | 'note',
    message: { text: f.description },
    locations: f.file ? [{
      physicalLocation: {
        artifactLocation: { uri: f.file.replace(targetDir + '/', '') },
        ...(f.line ? { region: { startLine: f.line } } : {}),
      },
    }] : undefined,
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  }, null, 2);
}

// HTML report for non-benchmark secure scans
function generateScanHtmlReport(scanResult: { findings: SecurityFinding[]; score: number; maxScore: number; projectType: string }, targetDir: string): string {
  const issues = scanResult.findings.filter(f => !f.passed && !f.fixed);
  const fixedFindings = scanResult.findings.filter(f => f.fixed);
  const score = scanResult.score;
  const scoreColor = score >= 90 ? '#22c55e' : score >= 70 ? '#eab308' : score >= 50 ? '#f97316' : '#ef4444';
  const gradeLetters = score >= 90 ? 'strong' : score >= 80 ? 'good' : score >= 70 ? 'moderate' : score >= 60 ? 'improving' : 'needs-attention';

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const severityColors: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  };

  const issueRows = issues
    .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
    .map(f => `
      <tr>
        <td><span class="severity-badge" style="background: ${severityColors[f.severity]}20; color: ${severityColors[f.severity]}; border: 1px solid ${severityColors[f.severity]}40;">${escapeHtml(f.severity.toUpperCase())}</span></td>
        <td><code>${escapeHtml(f.checkId)}</code></td>
        <td>${escapeHtml(f.description)}</td>
        <td>${f.file ? escapeHtml(f.file) + (f.line ? ':' + f.line : '') : ''}</td>
        <td>${f.fix ? escapeHtml(f.fix) : ''}</td>
      </tr>`).join('');

  const fixedRows = fixedFindings.map(f => `
      <tr>
        <td><span class="severity-badge" style="background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40;">FIXED</span></td>
        <td><code>${escapeHtml(f.checkId)}</code></td>
        <td>${escapeHtml(f.description)}</td>
        <td>${f.file ? escapeHtml(f.file) : ''}</td>
        <td>${f.fixMessage ? escapeHtml(f.fixMessage) : ''}</td>
      </tr>`).join('');

  const projectTypeLabel: Record<string, string> = {
    cli: 'CLI Tool', library: 'Library', webapp: 'Web App', api: 'API Server',
    mcp: 'MCP Server', openclaw: 'OpenClaw Agent', all: 'Project',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HackMyAgent Security Report | ${escapeHtml(require('path').basename(targetDir))}</title>
  <style>
    :root { --bg-primary: #0a0f1a; --bg-secondary: #111827; --bg-tertiary: #1f2937; --text-primary: #f1f5f9; --text-secondary: #94a3b8; --border: #334155; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 2rem; font-size: 14px; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .meta { color: var(--text-secondary); margin-bottom: 2rem; }
    .score-card { display: flex; align-items: center; gap: 2rem; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
    .grade { font-size: 0.75rem; font-weight: 700; width: 100px; height: 100px; display: flex; align-items: center; justify-content: center; border-radius: 50%; border: 3px solid ${scoreColor}; text-transform: uppercase; text-align: center; line-height: 1.2; padding: 0.5rem; }
    .score-details { flex: 1; }
    .score-num { font-size: 2rem; font-weight: 700; }
    .stats { display: flex; gap: 2rem; margin-top: 0.5rem; }
    .stat { color: var(--text-secondary); }
    .stat strong { color: var(--text-primary); }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th { text-align: left; padding: 0.75rem; background: var(--bg-secondary); border-bottom: 1px solid var(--border); color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; }
    td { padding: 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    code { background: var(--bg-tertiary); padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
    .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .section { margin-top: 2rem; }
    .section h2 { font-size: 1.2rem; margin-bottom: 0.5rem; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.85rem; }
    footer a { color: #3b82f6; }
    @media print { body { background: #fff; color: #000; } .score-card { border-color: #ccc; } th { background: #f3f4f6; } td { border-color: #e5e7eb; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>HackMyAgent Security Report</h1>
    <div class="meta">${escapeHtml(projectTypeLabel[scanResult.projectType] || 'Project')} - ${escapeHtml(require('path').basename(targetDir))} - ${new Date().toISOString().split('T')[0]}</div>

    <div class="score-card">
      <div class="grade" style="color: ${scoreColor};">${gradeLetters}</div>
      <div class="score-details">
        <div class="score-num" style="color: ${scoreColor};">${score}/${scanResult.maxScore}</div>
        <div class="stats">
          <span class="stat"><strong>${issues.length}</strong> issues</span>
          <span class="stat"><strong>${fixedFindings.length}</strong> fixed</span>
          <span class="stat"><strong>${scanResult.findings.filter(f => f.passed).length}</strong> passed</span>
        </div>
      </div>
    </div>

    ${issues.length > 0 ? `
    <div class="section">
      <h2>Issues (${issues.length})</h2>
      <table>
        <thead><tr><th>Severity</th><th>Check</th><th>Description</th><th>Location</th><th>Remediation</th></tr></thead>
        <tbody>${issueRows}</tbody>
      </table>
    </div>` : '<div class="section"><h2>No issues found</h2></div>'}

    ${fixedFindings.length > 0 ? `
    <div class="section">
      <h2>Auto-Fixed (${fixedFindings.length})</h2>
      <table>
        <thead><tr><th>Status</th><th>Check</th><th>Description</th><th>Location</th><th>Details</th></tr></thead>
        <tbody>${fixedRows}</tbody>
      </table>
    </div>` : ''}

    <footer>Generated by <a href="https://hackmyagent.com">HackMyAgent</a> v${VERSION}</footer>
  </div>
</body>
</html>`;
}

// Agent Security Profile (ASP) - our differentiator format
function generateAspOutput(benchmarkResult: BenchmarkResult, scanResult: { findings: SecurityFinding[]; projectType: string }, targetDir: string): string {
  const fs = require('fs');
  const path = require('path');

  // Try to get agent name from package.json or directory name
  let agentName = path.basename(targetDir);
  let agentVersion = '0.0.0';
  try {
    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      agentName = pkg.name || agentName;
      agentVersion = pkg.version || agentVersion;
    }
  } catch { /* ignore */ }

  // Analyze capabilities from findings
  const capabilities: Record<string, string> = {};
  const hasFilesystemAccess = scanResult.findings.some(f => f.checkId.includes('FS-') || f.description.toLowerCase().includes('filesystem'));
  const hasNetworkAccess = scanResult.findings.some(f => f.checkId.includes('NET-') || f.description.toLowerCase().includes('network'));
  const hasShellAccess = scanResult.findings.some(f => f.checkId.includes('SHELL-') || f.description.toLowerCase().includes('shell') || f.description.toLowerCase().includes('exec'));

  capabilities['filesystem'] = hasFilesystemAccess ? 'detected' : 'none';
  capabilities['network'] = hasNetworkAccess ? 'detected' : 'none';
  capabilities['shell'] = hasShellAccess ? 'detected' : 'none';

  // Credential hygiene
  const credentialFindings = scanResult.findings.filter(f => f.checkId.startsWith('CRED-'));
  const hardcodedCreds = credentialFindings.filter(f => !f.passed).length;

  // Supply chain status
  const supplyChainFindings = scanResult.findings.filter(f =>
    f.checkId.startsWith('SKILL-') || f.checkId.startsWith('HEARTBEAT-') || f.checkId.startsWith('DEP-')
  );
  const signedSkills = !supplyChainFindings.some(f => f.checkId === 'SKILL-001' && !f.passed);
  const pinnedDeps = !supplyChainFindings.some(f => f.checkId === 'DEP-001' && !f.passed);

  const asp = {
    specVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    generator: {
      name: 'HackMyAgent',
      version: VERSION,
      url: 'https://hackmyagent.com',
    },
    agent: {
      name: agentName,
      version: agentVersion,
      type: scanResult.projectType,
      path: targetDir,
    },
    securityPosture: {
      benchmark: 'OASB-1',
      benchmarkVersion: benchmarkResult.version,
      level: benchmarkResult.level,
      compliance: benchmarkResult.compliance,
      rating: benchmarkResult.rating,
      l1Compliance: benchmarkResult.l1Compliance,
      l2Compliance: benchmarkResult.l2Compliance,
      l3Compliance: benchmarkResult.l3Compliance,
    },
    capabilities,
    credentials: {
      hardcodedSecrets: hardcodedCreds,
      recommendation: hardcodedCreds > 0 ? 'Move secrets to environment variables or secrets manager' : 'No hardcoded credentials detected',
    },
    supplyChain: {
      signedComponents: signedSkills,
      pinnedDependencies: pinnedDeps,
      issues: supplyChainFindings.filter(f => !f.passed).map(f => ({
        id: f.checkId,
        description: f.description,
        remediation: f.fix,
      })),
    },
    categories: benchmarkResult.categories.map(cat => ({
      name: cat.category,
      compliance: cat.compliance,
      passed: cat.passed,
      failed: cat.failed,
      unverified: cat.unverified,
    })),
    failedControls: benchmarkResult.categories.flatMap(cat =>
      cat.controls.filter(c => c.status === 'failed').map(c => ({
        id: c.controlId,
        name: c.name,
        level: c.level,
        findings: c.findings,
        remediation: c.remediation,
      }))
    ),
    // Attestation placeholder - could be signed in future
    attestation: {
      timestamp: new Date().toISOString(),
      // signature: null, // Future: GPG or Sigstore signature
    },
  };

  return JSON.stringify(asp, null, 2);
}

function printBenchmarkReport(result: BenchmarkResult, verbose: boolean): void {
  const ratingColors: Record<BenchmarkResult['rating'], string> = {
    'Certified': colors.green,
    'Compliant': colors.green,
    'Passing': colors.yellow,
    'Needs Improvement': colors.yellow,
    'Not Passing': colors.red,
  };

  // Header
  console.log(`\n${result.benchmark} v${result.version}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  // Level and rating
  const levelNames: Record<BenchmarkLevel, string> = {
    'L1': 'Level 1 - Essential',
    'L2': 'Level 2 - Standard',
    'L3': 'Level 3 - Hardened',
  };
  console.log(`Level: ${levelNames[result.level]}`);
  console.log(`Rating: ${ratingColors[result.rating]}${result.rating}${RESET()}`);
  console.log(`Compliance: ${result.compliance}% (${result.passedControls}/${result.passedControls + result.failedControls} verified controls)`);
  if (result.unverifiedControls > 0) {
    console.log(`Unverified: ${result.unverifiedControls} controls require manual/forward verification`);
  }
  console.log();

  // Category breakdown
  console.log(`Categories:`);
  for (const catResult of result.categories) {
    const total = catResult.passed + catResult.failed;
    if (total === 0) {
      console.log(`  [.] ${catResult.category}: N/A (no controls at this level)`);
      continue;
    }
    const statusIcon = catResult.failed === 0 ? '[+]' : (catResult.passed > 0 ? '[~]' : '[-]');
    console.log(`  ${statusIcon} ${catResult.category}: ${catResult.passed}/${total} (${catResult.compliance}%)`);

    // Show failed controls
    if (verbose || catResult.failed > 0) {
      for (const ctrl of catResult.controls) {
        if (ctrl.status === 'failed') {
          console.log(`     [-] ${ctrl.controlId}: ${ctrl.name}`);
          if (verbose) {
            for (const finding of ctrl.findings) {
              console.log(`        └─ ${finding}`);
            }
          }
        } else if (verbose && ctrl.status === 'passed') {
          console.log(`     [+] ${ctrl.controlId}: ${ctrl.name}`);
        } else if (verbose && ctrl.status === 'unverified') {
          // Look up the original control to determine why it's unverified
          const originalControl = OASB_1_CATEGORIES
            .flatMap((c: BenchmarkCategory) => c.controls)
            .find((c: BenchmarkControl) => c.id === ctrl.controlId);
          const reason = originalControl && (originalControl.verification === 'manual' || originalControl.verification === 'forward')
            ? 'manual/forward'
            : 'no scanner data';
          console.log(`     [?] ${ctrl.controlId}: ${ctrl.name} (${reason})`);
        }
      }
    }
  }

  console.log();
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

  // Compliance breakdown by level
  if (verbose) {
    console.log(`\nCompliance by level: L1=${result.l1Compliance}% L2=${result.l2Compliance}% L3=${result.l3Compliance}%`);
    console.log(`Legend: [?] = Manual/Forward verification required`);
  }

  // Show appropriate next step based on current level
  if (result.level === 'L1') {
    console.log(`\nRun '${CLI_PREFIX} secure -b oasb-1 -l L2' for stricter checks.`);
  } else if (result.level === 'L2') {
    console.log(`\nRun '${CLI_PREFIX} secure -b oasb-1 -l L3' for hardened requirements.`);
  } else {
    console.log(`\nThis is the highest maturity level (L3 - Hardened).`);
  }
  console.log(`Spec: https://oasb.ai/oasb-1\n`);
}

// Package name resolution for community registry reporting
function resolvePackageName(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pkgJsonPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      if (pkg.name) return pkg.name;
    }
  } catch { /* ignore */ }
  // Fallback: use directory name, resolving "." to the actual directory name
  const path = require('path');
  const resolved = path.resolve(targetDir);
  const name = path.basename(resolved);
  // Skip names that are clearly not package names
  return name && name !== '.' && name !== '..' ? name : null;
}

function resolvePackageVersion(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pkgJsonPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      if (pkg.version) return pkg.version;
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Handle community contribution after a scan completes.
 *
 * Determines whether to contribute based on:
 *   1. --contribute / --no-contribute CLI flags (highest priority)
 *   2. ~/.opena2a/config.json contribute.enabled setting
 *
 * If contributing, queues an anonymized event to ~/.opena2a/contribute-queue.json
 * (compatible with @opena2a/contribute format) and flushes when threshold reached.
 *
 * Also records the scan and shows a delayed consent tip after the 3rd scan
 * if the user hasn't opted in or dismissed.
 */
async function handleContribution(
  contributeFlag: boolean | undefined,
  targetDir: string,
  findings: SecurityFinding[],
  durationMs: number,
  registryUrl?: string,
  format?: string,
): Promise<void> {
  try {
    const {
      isContributeEnabled,
      recordScanAndMaybeShowTip,
      buildScanEvent,
      queueAndMaybeFlush,
    } = await import('./telemetry');

    // Record scan count and maybe show the delayed consent tip
    const tip = recordScanAndMaybeShowTip();
    if (tip && format === 'text' && process.stdout.isTTY) {
      process.stdout.write(tip + '\n');
    }

    // Determine whether to contribute
    let shouldContribute: boolean;

    if (contributeFlag === true) {
      // --contribute flag: always contribute this scan
      shouldContribute = true;
    } else if (contributeFlag === false) {
      // --no-contribute flag: skip this scan
      shouldContribute = false;
    } else {
      // Check config
      shouldContribute = isContributeEnabled() === true;
    }

    if (!shouldContribute) return;

    // Build and queue contribution event (non-blocking, flushes at threshold)
    const packageName = resolvePackageName(targetDir);
    if (!packageName) return;

    const event = buildScanEvent(packageName, targetDir, findings, durationMs);
    await queueAndMaybeFlush(event, registryUrl, format === 'text');

    if (format === 'text') {
      process.stdout.write('Queued anonymized scan summary for OpenA2A Registry (--no-contribute to opt out)\n');
    }
  } catch {
    // Non-fatal: contribution failure must never crash the scan
  }
}

/**
 * Handle community contribution for scan-soul results.
 *
 * Converts SoulScanResult controls into SecurityFinding-like objects
 * for the contribution module, then delegates to handleContribution.
 */
async function handleSoulContribution(
  contributeFlag: boolean | undefined,
  targetDir: string,
  result: SoulScanResult,
  durationMs: number,
  registryUrl?: string,
  format?: string,
): Promise<void> {
  // Convert soul controls into SecurityFinding-shaped objects
  const findings: SecurityFinding[] = [];
  for (const domain of result.domains) {
    if (domain.skippedByProfile || domain.skippedByTier) continue;
    for (const ctrl of domain.controls) {
      findings.push({
        checkId: ctrl.id,
        name: ctrl.name,
        description: '',
        category: domain.domain,
        severity: 'medium' as Severity,
        passed: ctrl.passed,
        message: '',
        fixable: false,
      });
    }
  }

  await handleContribution(contributeFlag, targetDir, findings, durationMs, registryUrl, format);
}

program
  .command('secure')
  .description(`Scan and harden your agent setup

Performs 202 security checks across 39 categories:
  • Credentials: API key exposure, secrets in configs
  • MCP: Server configs, tool permissions, secrets
  • Network: TLS, interface bindings, CORS
  • Prompt: Injection defenses, role protection
  • Encryption: At-rest encryption, secure hashing
  • And 25 more categories...

Benchmark mode (--benchmark):
  oasb-1   OASB-1 infrastructure compliance (L1/L2/L3 levels)
           L1 = Essential (baseline), L2 = Standard, L3 = Hardened
  oasb-2   OASB-2 composite: infrastructure (50%) + governance (50%)
           Combines OASB-1 scan with scan-soul for a unified score

Output formats (--format):
  text   Human-readable terminal output (default)
  json   Machine-readable JSON
  sarif  GitHub Security tab / IDE integration
  html   Shareable compliance report

Severities: critical, high, medium, low
Exit code 1 if critical/high issues found (or non-compliant in benchmark mode).

Examples:
  $ hackmyagent secure                           Scan current directory
  $ hackmyagent secure ./my-project              Scan specific directory
  $ hackmyagent secure --fix                     Auto-fix issues
  $ hackmyagent secure -b oasb-1                 OASB-1 L1 compliance
  $ hackmyagent secure -b oasb-1 -l L2           OASB-1 L2 compliance
  $ hackmyagent secure -b oasb-1 -f sarif        SARIF for GitHub
  $ hackmyagent secure -b oasb-1 -f html -o report.html
  $ hackmyagent secure -b oasb-1 --fail-below 80 CI threshold
  $ hackmyagent secure -b oasb-2               OASB-2 composite (infra + governance)
  $ hackmyagent secure ./my-agent --publish    Scan and publish results to registry`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--ignore <checks>', 'Comma-separated check IDs to skip (e.g., CRED-001,GIT-002)')
  .option('--json', 'Output as JSON (deprecated: use --format json)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html (default: text)', 'text')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('--fail-below <percent>', 'Exit 1 if compliance below threshold (0-100)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .option('-b, --benchmark <name>', 'Run benchmark compliance check (e.g., oasb-1)')
  .option('-l, --level <level>', 'Benchmark level: L1 (Essential), L2 (Standard), L3 (Hardened)', 'L1')
  .option('-c, --category <name>', 'Filter to specific benchmark category')
  .option('--deep', 'Enable LLM-powered semantic analysis (requires ANTHROPIC_API_KEY)')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-report', 'Post results to OpenA2A Registry')
  .option('--no-registry', 'Skip auto-publishing results to OpenA2A Registry')
  .option('--version-id <id>', 'Registry version ID to report against')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', process.env.REGISTRY_URL || 'https://api.oa2a.org')
  .option('--registry-key <key>', 'Registry API key (default: REGISTRY_API_KEY env)')
  .option('--contribute', 'Share anonymized scan findings with OpenA2A Registry (overrides config)')
  .option('--no-contribute', 'Do not share findings for this scan (overrides config)')
  .option('--ci', 'CI mode: suppress interactive prompts, exit non-zero on findings')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; ignore?: string; json?: boolean; format?: string; output?: string; failBelow?: string; verbose?: boolean; benchmark?: string; level?: string; category?: string; deep?: boolean; publish?: boolean; registryReport?: boolean; registry?: boolean; versionId?: string; registryUrl?: string; registryKey?: string; contribute?: boolean; ci?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      // CI mode: force non-interactive defaults
      if (options.ci) {
        if (!options.format && !options.json) options.format = 'text';
        // In CI, never prompt -- only contribute if explicitly --contribute
        if (options.contribute === undefined) options.contribute = false;
      }

      // Check if directory exists
      if (!require('fs').existsSync(targetDir)) {
        console.error(`Error: Directory '${targetDir}' does not exist.`);
        process.exit(1);
      }

      // Parse ignore list
      const ignoreList = options.ignore
        ? options.ignore.split(',').map((s) => s.trim()).filter(Boolean)
        : [];

      // Validate benchmark flag if provided
      const isOasb2 = options.benchmark?.toLowerCase() === 'oasb-2';
      if (options.benchmark && !isOasb2 && !isValidBenchmark(options.benchmark)) {
        console.error(`Error: Unknown benchmark '${options.benchmark}'. Available: ${[...AVAILABLE_BENCHMARKS, 'oasb-2'].join(', ')}`);
        process.exit(1);
      }

      // Validate level if benchmark mode (not applicable for oasb-2)
      const validLevels = ['L1', 'L2', 'L3'];
      const level = (options.level?.toUpperCase() || 'L1') as BenchmarkLevel;
      if (options.benchmark && !isOasb2 && !validLevels.includes(level)) {
        console.error(`Error: Invalid level '${options.level}'. Use: L1, L2, or L3`);
        process.exit(1);
      }

      // Determine output format (--json is deprecated alias for --format json)
      const validFormats = ['text', 'json', 'sarif', 'html', 'asp'];
      const format = options.json ? 'json' : (options.format || 'text');
      if (!validFormats.includes(format)) {
        console.error(`Error: Invalid format '${format}'. Use: ${validFormats.join(', ')}`);
        process.exit(1);
      }

      // Parse fail threshold
      const failBelow = options.failBelow ? parseInt(options.failBelow, 10) : undefined;
      if (failBelow !== undefined && (isNaN(failBelow) || failBelow < 0 || failBelow > 100)) {
        console.error(`Error: --fail-below must be a number between 0 and 100`);
        process.exit(1);
      }

      // Only show progress for text output
      if (format === 'text') {
        if (options.dryRun) {
          console.log(`\nScanning ${targetDir} (dry-run)...\n`);
        } else {
          console.log(`\nScanning ${targetDir}...\n`);
        }
      }

      // Deep mode progress display
      const isDeep = options.deep ?? false;
      const onProgress = isDeep && format === 'text'
        ? (msg: string) => process.stdout.write(msg)
        : undefined;

      if (isDeep && format === 'text') {
        if (!process.env.ANTHROPIC_API_KEY) {
          console.log(`Layer 3: Semantic analysis — skipped (no ANTHROPIC_API_KEY)`);
          console.log(`  Tip: Add HackMyAgent as an MCP server for free LLM analysis:`);
          console.log(`  npx ${CLI_PREFIX} init-mcp\n`);
        }
      }

      const scanner = new HardeningScanner();
      const scanStartMs = Date.now();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: ignoreList,
        deep: isDeep,
        cliName: CLI_PREFIX,
        onProgress,
      });
      const scanDurationMs = Date.now() - scanStartMs;

      // OASB-2 composite mode: infrastructure (50%) + governance (50%)
      if (isOasb2) {
        const infraResult = generateBenchmarkReport(
          result.allFindings || result.findings,
          level,
          options.category,
        );

        const { SoulScanner } = await import('./soul/index.js');
        const soulScanner = new SoulScanner();
        const govResult = await soulScanner.scanSoul(targetDir);

        const infraScore = infraResult.compliance ?? 0;
        const govScore = govResult.score;
        const compositeScore = Math.round((infraScore + govScore) / 2);

        if (format === 'json') {
          const jsonOutput = JSON.stringify({
            benchmark: 'OASB-2',
            infraScore,
            govScore,
            compositeScore,
            conformance: govResult.conformance,
            infraResult,
            govResult,
          }, null, 2);
          if (options.output) {
            require('fs').writeFileSync(options.output, jsonOutput);
            console.error(`Report written to ${options.output}`);
          } else {
            const fs = require('fs');
            fs.writeFileSync(1, jsonOutput + '\n');
          }
        } else {
          process.stdout.write('\nOASB v2 Composite Security Assessment\n');
          process.stdout.write('----------------------------------------------------\n');
          process.stdout.write(`Infrastructure Score (OASB-1): ${infraScore}%\n`);
          process.stdout.write(`Governance Score (OASB-2):     ${govScore}/100\n`);
          process.stdout.write('----------------------------------------------------\n');
          process.stdout.write(`Composite Score:               ${compositeScore}/100\n`);
          process.stdout.write(`Conformance:                   ${govResult.conformance.toUpperCase()}\n`);
          process.stdout.write('\n');

          // Show infra report then governance report
          printBenchmarkReport(infraResult, options.verbose ?? false);

          process.stdout.write('\nGovernance Domains (scan-soul):\n');
          for (const domain of govResult.domains) {
            const label = (domain.domain + ':').padEnd(26);
            process.stdout.write(`  ${label}${domain.passed}/${domain.total}  (${domain.percentage}%)\n`);
          }
          if (govResult.criticalFloor) {
            process.stdout.write(`\nCritical Floor: APPLIED (${govResult.criticalMissing.join(', ')} missing)\n`);
          }
          process.stdout.write('\n');
        }

        if (failBelow !== undefined && compositeScore < failBelow) {
          console.error(`Composite score ${compositeScore} is below threshold ${failBelow}`);
          process.exit(1);
        }
        return;
      }

      // Benchmark mode - output compliance report
      if (options.benchmark) {
        // Use allFindings (unfiltered) for accurate benchmark evaluation
        const benchmarkResult = generateBenchmarkReport(
          result.allFindings || result.findings,
          level,
          options.category
        );

        // Output based on format
        let output: string;
        switch (format) {
          case 'json':
            output = JSON.stringify(benchmarkResult, null, 2);
            break;
          case 'sarif':
            output = generateSarifOutput(benchmarkResult, result.findings, targetDir);
            break;
          case 'html':
            output = generateHtmlReport(benchmarkResult);
            break;
          case 'asp':
            output = generateAspOutput(benchmarkResult, result, targetDir);
            break;
          default: // text
            printBenchmarkReport(benchmarkResult, options.verbose ?? false);
            output = '';
        }

        // Write output
        if (output) {
          if (options.output) {
            require('fs').writeFileSync(options.output, output);
            console.error(`Report written to ${options.output}`);
          } else {
            console.log(output);
          }
        }

        // Check fail threshold
        if (failBelow !== undefined && benchmarkResult.compliance < failBelow) {
          console.error(`Compliance ${benchmarkResult.compliance}% is below threshold ${failBelow}%`);
          process.exit(1);
        }

        // Exit with non-zero if failing or needs improvement (default behavior)
        if (failBelow === undefined && (benchmarkResult.rating === 'Not Passing' || benchmarkResult.rating === 'Needs Improvement')) {
          process.exit(1);
        }
        return;
      }

      if (format === 'json') {
        // Run publish in JSON mode and include result in output
        let publishStatus: Record<string, unknown> | undefined;
        if (options.publish && options.registry !== false) {
          try {
            const { publishScanResults } = await import('./registry/publish');
            const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const publishData = {
                packageName,
                packageVersion: resolvePackageVersion(targetDir) ?? undefined,
                directory: targetDir,
                hardeningFindings: result.findings,
              };
              const publishResult = await publishScanResults(publishData, registryUrl);
              publishStatus = { ...publishResult, registryUrl };
            } else {
              publishStatus = { success: false, error: 'Could not determine package name' };
            }
          } catch (publishErr: unknown) {
            const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
            publishStatus = { success: false, error: msg };
          }
        }

        const jsonOutput = publishStatus ? { ...result, publish: publishStatus } : result;
        if (options.output) {
          require('fs').writeFileSync(options.output, JSON.stringify(jsonOutput, null, 2) + '\n');
          console.error(`Report written to ${options.output}`);
        } else {
          writeJsonStdout(jsonOutput);
        }
        // Community contribution (non-blocking, runs in JSON mode too)
        await handleContribution(options.contribute, targetDir, result.findings, scanDurationMs, options.registryUrl, format);
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exitCode = 1;
        return;
      }

      // Handle SARIF/HTML/ASP for non-benchmark mode
      if (format === 'sarif') {
        const output = generateScanSarif(result.findings, targetDir);
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          console.log(output);
        }
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exit(1);
        return;
      }

      if (format === 'html') {
        const output = generateScanHtmlReport(result, targetDir);
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          console.log(output);
        }
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exit(1);
        return;
      }

      // Filter to only show failed findings (issues)
      const issues = result.findings.filter((f) => !f.passed && !f.fixed);
      const fixedFindings = result.findings.filter((f) => f.fixed);

      // Print header - clean and simple
      const projectTypeLabel = {
        cli: 'CLI Tool',
        library: 'Library',
        webapp: 'Web App',
        api: 'API Server',
        mcp: 'MCP Server',
        openclaw: 'OpenClaw Agent',
        all: 'Project',
      }[result.projectType] || 'Project';

      let scoreExtra = '';
      if (result.semanticAnalysis) {
        const sa = result.semanticAnalysis;
        scoreExtra = ` | ${sa.layer2Findings} deep analysis finding${sa.layer2Findings === 1 ? '' : 's'}`;
        if (sa.layer3Findings > 0) {
          scoreExtra += `, ${sa.layer3Findings} AI-assisted`;
          if (sa.llmCost !== undefined) scoreExtra += ` ($${sa.llmCost.toFixed(3)})`;
          if (sa.cachedResults) scoreExtra += ` (${sa.cachedResults} cached)`;
        }
      }
      console.log(`${projectTypeLabel} | Score: ${result.score}/${result.maxScore}${scoreExtra}`);
      if (issues.length > 0) {
        const recoverable = Math.min(result.maxScore - result.score, result.maxScore);
        console.log(`  Path forward: +${recoverable} recoverable by addressing ${issues.length} issue${issues.length === 1 ? '' : 's'}`);
      }
      console.log('');

      // No issues? Say so and exit
      if (issues.length === 0 && fixedFindings.length === 0) {
        console.log(`${colors.green}No issues found.${RESET()}\n`);
      } else if (issues.length > 0) {
        // Print issues - clean format with fixable count
        const fixableCount = issues.filter((f: SecurityFinding) => f.fixable).length;
        const fixableNote = fixableCount > 0
          ? ` (${fixableCount} auto-fixable with \`${CLI_PREFIX} secure --fix\`)`
          : '';
        console.log(`${issues.length} issue${issues.length === 1 ? '' : 's'} found${fixableNote}:\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          // Format: SEVERITY  [DRY RUN] Would fix: file:line
          //         Description
          //         Fix: command
          const dryRunPrefix = (finding as any).wouldFix ? `${colors.cyan}[DRY RUN] Would fix: ${RESET()}` : '';
          console.log(`${display.color()}${display.symbol} ${finding.severity.toUpperCase()}${RESET()}  ${dryRunPrefix}${location}`);
          console.log(`       ${finding.description}`);
          if (finding.fix) {
            console.log(`       ${colors.cyan}Fix:${RESET()} ${finding.fix}`);
          }
          if (options.verbose) {
            console.log(`       ${colors.dim}Check: ${finding.checkId} | Category: ${finding.category}${RESET()}`);
            if (finding.file) {
              console.log(`       ${colors.dim}File: ${finding.file}${finding.line ? ` (line ${finding.line})` : ''}${RESET()}`);
            }
            if (finding.message && finding.message !== finding.description) {
              console.log(`       ${colors.dim}Detail: ${finding.message}${RESET()}`);
            }
            if (finding.details && Object.keys(finding.details).length > 0) {
              for (const [key, value] of Object.entries(finding.details)) {
                console.log(`       ${colors.dim}${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}${RESET()}`);
              }
            }
          }
          console.log();
        }

        // Severity breakdown summary
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const f of issues) {
          severityCounts[f.severity]++;
        }
        const summaryParts: string[] = [];
        if (severityCounts.critical > 0) summaryParts.push(`${colors.brightRed}Critical: ${severityCounts.critical}${RESET()}`);
        if (severityCounts.high > 0) summaryParts.push(`${colors.red}High: ${severityCounts.high}${RESET()}`);
        if (severityCounts.medium > 0) summaryParts.push(`${colors.yellow}Medium: ${severityCounts.medium}${RESET()}`);
        if (severityCounts.low > 0) summaryParts.push(`${colors.green}Low: ${severityCounts.low}${RESET()}`);
        if (summaryParts.length > 0) {
          console.log(`${summaryParts.join(' | ')}\n`);
        }

        // Dry-run summary
        if (result.dryRun) {
          const wouldFixCount = issues.filter((f: any) => f.wouldFix).length;
          if (wouldFixCount > 0) {
            console.log(`${colors.cyan}Dry run complete:${RESET()} ${wouldFixCount} issue${wouldFixCount === 1 ? '' : 's'} auto-fixable. Run without --dry-run to apply.`);
          }
          console.log(`  No changes were made.\n`);
        }
      }

      // Print fixed findings with detailed summary
      if (fixedFindings.length > 0) {
        const verifiedCount = fixedFindings.filter((f: SecurityFinding) => (f as any).fixVerified).length;
        const unverifiedCount = fixedFindings.filter((f: SecurityFinding) => (f as any).fixVerified === false).length;
        console.log(`${colors.green}Fixed ${fixedFindings.length} issue${fixedFindings.length === 1 ? '' : 's'}${verifiedCount > 0 ? ` (${verifiedCount} verified)` : ''}:${RESET()}`);
        for (const finding of fixedFindings) {
          const location = finding.file ? (finding.line ? `${finding.file}:${finding.line}` : finding.file) : '';
          const verified = (finding as any).fixVerified;
          const verifyIcon = verified === true ? `${colors.green}✓✓${RESET()}` : verified === false ? `${colors.yellow}✓?${RESET()}` : `${colors.green}✓${RESET()}`;
          console.log(`  ${verifyIcon} [${finding.checkId}] ${location} - ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`    ${colors.cyan}→${RESET()} ${finding.fixMessage}`);
          }
        }
        if (unverifiedCount > 0) {
          console.log(`\n  ${colors.yellow}${unverifiedCount} fix${unverifiedCount === 1 ? '' : 'es'} could not be verified. Review these manually.${RESET()}`);
        }
        console.log();

        // Remaining fixable issues
        const remainingFixable = issues.filter((f: SecurityFinding) => f.fixable && !f.fixed);
        if (remainingFixable.length > 0) {
          console.log(`${colors.yellow}${remainingFixable.length} more issue${remainingFixable.length === 1 ? '' : 's'} can be auto-fixed.${RESET()} Run \`${CLI_PREFIX} secure --fix\` again.\n`);
        }

        if (result.backupPath) {
          console.log(`${colors.yellow}Backup created:${RESET()} ${result.backupPath}`);
          console.log(`${colors.yellow}Something wrong?${RESET()} Run \`${CLI_PREFIX} rollback ${directory}\` to undo all changes.\n`);
        }
      }

      // Registry reporting: only when explicitly requested via --version-id (CI) or --registry-report
      // Community contributions are handled by the opena2a CLI wrapper, not HMA directly
      if (options.versionId || options.registryReport) {
        try {
          const core = await import('./index');
          const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';

          if (options.versionId) {
            // Authenticated path: existing behavior (version-id + API key)
            const registryKey = options.registryKey || process.env.REGISTRY_API_KEY;
            if (!registryKey) {
              console.error('Error: --registry-key or REGISTRY_API_KEY env is required when using --version-id');
              process.exit(1);
            }
            const client = new core.RegistryClient({ registryUrl, apiKey: registryKey });
            const payload = core.buildScanReport(options.versionId, result.findings);
            await client.reportScanResult(payload);
            console.log(`Registry: scan results reported for version ${options.versionId}`);
          } else if (typeof core.buildCommunityReport === 'function') {
            // Community path: request scan token, then submit results
            const client = new core.RegistryClient({ registryUrl, apiKey: '' });
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const packageVersion = resolvePackageVersion(targetDir);
              const tokenResp = typeof client.requestScanToken === 'function'
                ? await client.requestScanToken(packageName, { version: packageVersion ?? undefined })
                : null;
              const payload = core.buildCommunityReport(packageName, result.findings, {
                version: packageVersion ?? undefined,
              });
              const resp = typeof client.reportCommunityResult === 'function'
                ? await client.reportCommunityResult(payload, tokenResp?.scanToken)
                : { status: 'skipped' };
              if (resp.status === 'accepted') {
                console.log('Registry: scan shared with OpenA2A community');
              }
            }
          }
        } catch (_reportErr: any) {
          // Silently ignore registry errors - they are not relevant to local scan results
        }
      }

      // Publish: push results to registry when --publish is used
      if (options.publish && options.registry === false) {
        if (format === 'text') {
          console.log('\nPublish skipped: --no-registry flag is active.');
        }
      } else if (options.publish) {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';
          const packageName = resolvePackageName(targetDir);

          if (!packageName) {
            console.error('\nCould not determine package name. Publish requires a package.json with a name field.');
          } else {
            if (format === 'text') {
              console.log('\nPublishing results to registry...\n');
            }

            const publishData = {
              packageName,
              packageVersion: resolvePackageVersion(targetDir) ?? undefined,
              directory: targetDir,
              hardeningFindings: result.findings,
            };

            const publishResult = await publishScanResults(publishData, registryUrl);
            if (format === 'text') {
              console.log(formatPublishOutput(publishResult, publishData, registryUrl));
              console.log();
            } else if (format === 'json') {
              // Append publish result to JSON output in a separate log
              console.error(JSON.stringify({ publish: publishResult }, null, 2));
            }
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          console.error(`\nFailed to publish to registry: ${msg}`);
          console.error('Scan results are still available locally.');
        }
      }

      // Community contribution: share anonymized findings with OpenA2A Registry
      await handleContribution(options.contribute, targetDir, result.findings, scanDurationMs, options.registryUrl, format);

      // Star prompt (interactive TTY only, text format only)
      if (process.stdout.isTTY) {
        console.log(`${colors.cyan}Helpful?${RESET()} Star the project: https://github.com/opena2a-org/opena2a\n`);
      }

      // Exit with non-zero if critical/high issues remain (or any issues in --ci mode)
      if (options.ci && issues.length > 0) {
        process.exit(1);
      }
      const criticalOrHigh = issues.filter(
        (f: SecurityFinding) => f.severity === 'critical' || f.severity === 'high'
      );
      if (criticalOrHigh.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Severity display for external scan findings
const FINDING_SEVERITY_DISPLAY: Record<FindingSeverity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
};

function groupExternalFindingsBySeverity(
  findings: ExternalFinding[]
): Record<FindingSeverity, ExternalFinding[]> {
  const grouped: Record<FindingSeverity, ExternalFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

// OpenClaw-specific check categories
const OPENCLAW_CATEGORIES = ['skill', 'heartbeat', 'gateway', 'config', 'supply'];

function detectOpenClawDirectory(providedDir: string): string {
  const os = require('os');
  const fs = require('fs');
  const path = require('path');

  // If user provided a directory, use it
  if (providedDir && providedDir !== '') {
    return providedDir.startsWith('/') ? providedDir : path.join(process.cwd(), providedDir);
  }

  // Auto-detect common OpenClaw/Moltbot installation directories
  const homeDir = os.homedir();
  const candidates = [
    path.join(homeDir, '.openclaw'),
    path.join(homeDir, '.moltbot'),
    path.join(homeDir, '.clawdbot'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Fall back to current working directory
  return process.cwd();
}

function filterOpenClawFindings(findings: SecurityFinding[]): SecurityFinding[] {
  return findings.filter((f) => {
    const checkId = f.checkId.toLowerCase();
    return OPENCLAW_CATEGORIES.some((cat) => checkId.includes(cat));
  });
}

function assessRiskLevel(findings: SecurityFinding[]): { level: string; color: string; description: string } {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;

  if (criticalCount > 0) {
    return {
      level: 'Critical',
      color: colors.brightRed,
      description: `${criticalCount} critical finding(s) with recommended fixes available.`,
    };
  }
  if (highCount > 0) {
    return {
      level: 'High',
      color: colors.red,
      description: `${highCount} high-severity finding(s) detected. Fixes available below.`,
    };
  }
  if (mediumCount > 0) {
    return {
      level: 'Moderate',
      color: colors.yellow,
      description: 'Some findings detected. Review the recommendations below.',
    };
  }
  if (findings.length === 0) {
    return {
      level: 'None',
      color: colors.dim,
      description: `No OpenClaw configuration detected. Run \`${CLI_PREFIX} secure\` for a full scan.`,
    };
  }
  return {
    level: 'Low',
    color: colors.green,
    description: 'No critical or high findings detected.',
  };
}

program
  .command('secure-openclaw')
  .description(`Security scan specifically for OpenClaw/Moltbot installations

Performs focused security checks for OpenClaw agent deployments:
  • Skill validation: Permission scopes, signature verification
  • Heartbeat security: Endpoint exposure, authentication
  • Gateway configs: Routing rules, rate limiting
  • Config files: Secret exposure, insecure defaults
  • Supply chain: Dependency vulnerabilities, integrity

Auto-detects ~/.openclaw, ~/.moltbot, or ~/.clawdbot directories.
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent secure-openclaw                  Scan auto-detected directory
  $ hackmyagent secure-openclaw ~/.openclaw      Scan specific directory
  $ hackmyagent secure-openclaw --fix            Auto-fix issues
  $ hackmyagent secure-openclaw --json           JSON output for CI`)
  .argument('[directory]', 'Directory to scan (default: ~/.openclaw or ~/.moltbot)', '')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = detectOpenClawDirectory(directory);

      if (!options.json) {
        console.log(`\nOpenClaw Security Report`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        if (options.dryRun) {
          console.log(`Scanning ${targetDir} (dry-run - previewing fixes)...\n`);
        } else if (options.fix) {
          console.log(`Scanning and fixing ${targetDir}...\n`);
          console.log(`${colors.yellow}Auto-fix will:${RESET()}`);
          console.log(`  • Bind gateway to 127.0.0.1 (local-only)`);
          console.log(`  • Replace plaintext tokens with env var references`);
          console.log(`  • Enable approval confirmations`);
          console.log(`  • Enable sandbox mode`);
          console.log(`\n${colors.cyan}A backup will be created for rollback if needed.${RESET()}\n`);
        } else {
          console.log(`Scanning ${targetDir}...\n`);
        }
      }

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: [],
        cliName: CLI_PREFIX,
      });

      // Filter to OpenClaw-specific findings
      const allOpenClawFindings = filterOpenClawFindings(result.findings);
      const issues = allOpenClawFindings.filter((f) => !f.passed && !f.fixed);
      const fixedFindings = allOpenClawFindings.filter((f) => f.fixed);
      const passedFindings = allOpenClawFindings.filter((f) => f.passed);

      if (options.json) {
        const jsonOutput = {
          target: targetDir,
          riskLevel: assessRiskLevel(issues).level,
          totalChecks: allOpenClawFindings.length,
          issues: issues.length,
          fixed: fixedFindings.length,
          passed: passedFindings.length,
          findings: allOpenClawFindings,
        };
        writeJsonStdout(jsonOutput);
        return;
      }

      // Risk assessment
      const risk = assessRiskLevel(issues);
      console.log(`Risk Level: ${risk.color}${risk.level}${RESET()}`);
      console.log(`${risk.description}\n`);

      // Summary stats
      console.log(`Checks: ${allOpenClawFindings.length} total | ${issues.length} issues | ${fixedFindings.length} fixed | ${passedFindings.length} passed\n`);

      // Show issues
      if (issues.length > 0) {
        console.log(`${colors.red}Findings:${RESET()}\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          const sevLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
          console.log(`${display.color()}${display.symbol} [${finding.checkId}] ${sevLabel}${RESET()}`);
          console.log(`   ${finding.description}`);
          if (location) {
            console.log(`   File: ${location}`);
          }
          if (finding.fix) {
            console.log(`   ${colors.cyan}Recommended fix:${RESET()} ${finding.fix}`);
          }
          console.log();
        }
      } else {
        console.log(`${colors.green}No OpenClaw-specific issues found.${RESET()}\n`);
      }

      // Show fixed findings
      if (fixedFindings.length > 0) {
        console.log(`${colors.green}Auto-Remediation Applied:${RESET()}\n`);
        for (const finding of fixedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`     ${colors.cyan}→${RESET()} ${finding.fixMessage}`);
          }
        }
        console.log();

        if (result.backupPath) {
          console.log(`${colors.yellow}Backup created:${RESET()} ${result.backupPath}`);
          console.log(`${colors.yellow}To rollback:${RESET()} ${CLI_PREFIX} rollback ${targetDir}`);
          console.log();
          console.log(`${colors.cyan}Note:${RESET()} If you replaced tokens with env vars, set OPENCLAW_AUTH_TOKEN`);
          console.log(`      in your environment before starting OpenClaw.\n`);
        }
      }

      // Show passed checks in verbose mode
      if (options.verbose && passedFindings.length > 0) {
        console.log(`${colors.green}Passed Checks:${RESET()}`);
        for (const finding of passedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
        }
        console.log();
      }

      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      console.log(`Run '${CLI_PREFIX} secure' for a full security scan.\n`);

      // Exit with non-zero if critical/high issues remain
      const criticalOrHigh = issues.filter(
        (f: SecurityFinding) => f.severity === 'critical' || f.severity === 'high'
      );
      if (criticalOrHigh.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// NemoClaw-specific helpers
const NEMOCLAW_CHECK_CATEGORIES = NEMOCLAW_CATEGORIES;

function detectNemoClawDirectory(providedDir: string): string {
  const os = require('os');
  const fs = require('fs');
  const path = require('path');

  if (providedDir && providedDir !== '') {
    return providedDir.startsWith('/') ? providedDir : path.join(process.cwd(), providedDir);
  }

  const homeDir = os.homedir();
  const candidates = [
    path.join(homeDir, '.nemoclaw'),
    path.join(homeDir, '.openshell'),
    path.join(homeDir, '.openclaw'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return process.cwd();
}

function filterNemoClawFindings(findings: SecurityFinding[]): SecurityFinding[] {
  return findings.filter((f) => {
    const checkId = f.checkId.toUpperCase();
    return checkId.startsWith('HMA-NMC-');
  });
}

function assessNemoClawRiskLevel(findings: SecurityFinding[]): { level: string; color: string; description: string } {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;

  if (criticalCount > 0) {
    return {
      level: 'Critical',
      color: colors.brightRed,
      description: `${criticalCount} critical finding(s) with recommended fixes available.`,
    };
  }
  if (highCount > 0) {
    return {
      level: 'High',
      color: colors.red,
      description: `${highCount} high-severity finding(s) detected. Fixes available below.`,
    };
  }
  if (mediumCount > 0) {
    return {
      level: 'Moderate',
      color: colors.yellow,
      description: 'Some findings detected. Review the recommendations below.',
    };
  }
  if (findings.length === 0) {
    return {
      level: 'None',
      color: colors.dim,
      description: `No NemoClaw installation detected. Run \`${CLI_PREFIX} secure\` for a full scan.`,
    };
  }
  return {
    level: 'Low',
    color: colors.green,
    description: 'No critical or high findings detected.',
  };
}

program
  .command('secure-nemoclaw')
  .description(`Security scan for NVIDIA NemoClaw installations

Performs focused security checks for NemoClaw sandbox deployments:
  - Secrets: NVIDIA API key exposure in configs, logs, Docker, shell history
  - Network: Gateway/k3s/inference port binding, Docker socket, egress policies
  - Skills: Blueprint integrity, skill verification, directory permissions
  - Process: Sandbox privileges, seccomp/Landlock enforcement, root execution
  - OpenClaw layer: Inherited misconfigs that survive NemoClaw sandboxing

Auto-detects ~/.nemoclaw, ~/.openshell, or ~/.openclaw directories.
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent secure-nemoclaw                  Scan auto-detected directory
  $ hackmyagent secure-nemoclaw ~/.nemoclaw      Scan specific directory
  $ hackmyagent secure-nemoclaw --json           JSON output for CI`)
  .argument('[directory]', 'Directory to scan (default: ~/.nemoclaw or ~/.openshell)', '')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = detectNemoClawDirectory(directory);

      if (!options.json) {
        console.log(`\nNemoClaw Security Report`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        console.log(`Scanning ${targetDir}...\n`);
      }

      const scanner = new NemoClawScanner();
      const findings = await scanner.scan(targetDir, {});

      // Enrich with taxonomy
      const { enrichWithTaxonomy } = require('./hardening/taxonomy');
      enrichWithTaxonomy(findings);

      const issues = findings.filter((f: SecurityFinding) => !f.passed);
      const passedFindings = findings.filter((f: SecurityFinding) => f.passed);

      if (options.json) {
        const jsonOutput = {
          target: targetDir,
          riskLevel: assessNemoClawRiskLevel(issues).level,
          totalChecks: findings.length,
          issues: issues.length,
          passed: passedFindings.length,
          findings: findings,
        };
        writeJsonStdout(jsonOutput);
        return;
      }

      // Risk assessment
      const risk = assessNemoClawRiskLevel(issues);
      console.log(`Risk Level: ${risk.color}${risk.level}${RESET()}`);
      console.log(`${risk.description}\n`);

      // Summary stats
      console.log(`Checks: ${findings.length} total | ${issues.length} issues | ${passedFindings.length} passed\n`);

      // Show issues
      if (issues.length > 0) {
        console.log(`${colors.red}Findings:${RESET()}\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          const sevLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
          console.log(`${display.color()}${display.symbol} [${finding.checkId}] ${sevLabel}${RESET()}`);
          console.log(`   ${finding.description}`);
          if (location) {
            console.log(`   File: ${location}`);
          }
          if (finding.fix) {
            console.log(`   ${colors.cyan}Recommended fix:${RESET()} ${finding.fix}`);
          }
          console.log();
        }
      } else {
        console.log(`${colors.green}No NemoClaw-specific issues found.${RESET()}\n`);
      }

      // Show passed checks in verbose mode
      if (options.verbose && passedFindings.length > 0) {
        console.log(`${colors.green}Passed Checks:${RESET()}`);
        for (const finding of passedFindings) {
          console.log(`  ${colors.green}[ok]${RESET()} [${finding.checkId}] ${finding.name}`);
        }
        console.log();
      }

      // Shodan self-check guidance
      if (issues.some((f: SecurityFinding) => f.category === 'network')) {
        console.log(`${colors.yellow}Internet Exposure Check:${RESET()}`);
        console.log(`  Check if your instance is visible on Shodan:`);
        console.log(`  https://www.shodan.io/host/<YOUR-IP>`);
        console.log(`  Known NemoClaw dorks: port:18789, port:6443 ssl.cert.subject.cn:"k3s-serving"\n`);
      }

      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      console.log(`Run '${CLI_PREFIX} secure-openclaw' for OpenClaw-specific checks.`);
      console.log(`Run '${CLI_PREFIX} secure' for a full security scan.\n`);

      // Exit with non-zero if critical/high issues remain
      const criticalOrHigh = issues.filter(
        (f: SecurityFinding) => f.severity === 'critical' || f.severity === 'high'
      );
      if (criticalOrHigh.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

program
  .command('scan')
  .description(`Scan external target for exposed MCP endpoints

Detects externally exposed:
  • MCP SSE/tools endpoints
  • Configuration files (mcp.json, settings)
  • API keys in responses
  • Debug/admin interfaces

Scoring: strong (90-100), good (80-89), moderate (70-79), improving (60-69), needs-attention (<60)
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent scan example.com
  $ hackmyagent scan 192.168.1.100 -p 3000,8080
  $ hackmyagent scan example.com --verbose
  $ hackmyagent scan example.com --json`)
  .argument('<target>', 'Target hostname or IP address')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-p, --ports <ports>', 'Comma-separated ports to scan (default: common MCP ports)')
  .option('-t, --timeout <ms>', 'Connection timeout in milliseconds', '5000')
  .option('-v, --verbose', 'Show detailed finding information')
  .action(
    async (
      target: string,
      options: { json?: boolean; ports?: string; timeout?: string; verbose?: boolean }
    ) => {
      try {
        if (!options.json) {
          console.log(`\nScanning ${target}...\n`);
        }

        const scanner = new ExternalScanner();
        const customPorts = options.ports
          ? options.ports.split(',').map((p) => parseInt(p.trim(), 10))
          : undefined;

        const result = await scanner.scan(target, {
          ports: customPorts,
          timeout: parseInt(options.timeout ?? '5000', 10),
        });

        if (options.json) {
          writeJsonStdout(result);
          return;
        }

        // Print header
        const gradeColor =
          result.grade === 'strong' || result.grade === 'good'
            ? colors.green
            : result.grade === 'moderate'
              ? colors.yellow
              : colors.red;
        console.log(`Target: ${result.target}`);
        console.log(`Score: ${gradeColor}${result.score}/100 (${result.grade})${RESET()}`);
        console.log(`Open Ports: ${result.openPorts.length > 0 ? result.openPorts.join(', ') : 'None detected'}`);
        console.log(`Duration: ${result.duration}ms\n`);

        if (result.findings.length === 0) {
          console.log(`${colors.green}[+] No security issues found!${RESET()}\n`);
          return;
        }

        // Group findings by severity
        const grouped = groupExternalFindingsBySeverity(result.findings);

        // Print findings by severity
        for (const severity of ['critical', 'high', 'medium', 'low'] as FindingSeverity[]) {
          const findings = grouped[severity];
          if (findings.length === 0) continue;

          const display = FINDING_SEVERITY_DISPLAY[severity];
          console.log(
            `${display.color()}${display.symbol} ${severity.toUpperCase()} (${findings.length})${RESET()}`
          );

          for (const finding of findings) {
            console.log(`   • [${finding.checkId}] ${finding.title}`);
            if (finding.port) {
              console.log(`     Port: ${finding.port}${finding.path ? `, Path: ${finding.path}` : ''}`);
            }
            if (options.verbose) {
              console.log(`     ${finding.description}`);
              console.log(`     Evidence: ${finding.evidence}`);
              console.log(`     Impact: ${finding.impact}`);
              console.log(`     Fix: ${finding.fix}`);
            }
          }
          console.log();
        }

        // Exit with non-zero if critical/high issues found
        const criticalOrHigh = result.findings.filter(
          (f) => f.severity === 'critical' || f.severity === 'high'
        );
        if (criticalOrHigh.length > 0) {
          process.exit(1);
        }
      } catch (error) {
        console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        process.exit(1);
      }
    }
  );

program
  .command('rollback')
  .description(`Rollback auto-fix changes to the most recent backup

Restores files to their state before the last --fix operation.
Backups are stored in .hackmyagent-backup/ with timestamps.

Examples:
  $ hackmyagent rollback              Rollback current directory
  $ hackmyagent rollback ./my-project Rollback specific directory`)
  .argument('[directory]', 'Directory to rollback (defaults to current directory)', '.')
  .action(async (directory: string) => {
    try {
      const targetDir = require("path").resolve(directory);

      console.log(`\nRolling back changes in ${targetDir}...\n`);

      const scanner = new HardeningScanner();
      await scanner.rollback(targetDir);

      console.log(`${colors.green}[+] Rollback successful!${RESET()}`);
      console.log('   All auto-fix changes have been reverted.\n');
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Attack command - adversarial security testing
const ATTACK_CATEGORY_NAMES = Object.keys(ATTACK_CATEGORIES) as AttackCategory[];

program
  .command('attack')
  .description(`Adversarial security testing for AI agents

Red team your AI agent with ${PAYLOAD_STATS.total} attack payloads across 7 categories:
  • Prompt Injection: ${PAYLOAD_STATS.byCategory['prompt-injection']} payloads
  • Jailbreaking: ${PAYLOAD_STATS.byCategory['jailbreak']} payloads
  • Data Exfiltration: ${PAYLOAD_STATS.byCategory['data-exfiltration']} payloads
  • Capability Abuse: ${PAYLOAD_STATS.byCategory['capability-abuse']} payloads
  • Context Manipulation: ${PAYLOAD_STATS.byCategory['context-manipulation']} payloads
  • MCP Exploitation: ${PAYLOAD_STATS.byCategory['mcp-exploitation']} payloads
  • A2A Attacks: ${PAYLOAD_STATS.byCategory['a2a-attack']} payloads

Intensity levels (controls how many payloads run):
  passive     Observation only (${PAYLOAD_STATS.byIntensity.passive} payloads)
  active      Standard payloads (${PAYLOAD_STATS.byIntensity.passive + PAYLOAD_STATS.byIntensity.active} payloads, default)
  aggressive  All payloads including creative/risky (${PAYLOAD_STATS.total} payloads)

Target types:
  api         OpenAI/Anthropic chat completions (default)
  mcp         MCP JSON-RPC server (tools/call, tools/list)
  a2a         A2A agent messaging endpoint (/a2a/message)
  local       Local simulation (no API calls)

Examples:
  $ hackmyagent attack https://api.example.com/v1/chat
  $ hackmyagent attack https://api.example.com --intensity aggressive
  $ hackmyagent attack https://api.example.com --category prompt-injection
  $ hackmyagent attack --local --system-prompt "You are a helpful assistant"
  $ hackmyagent attack https://api.example.com -f sarif -o results.sarif
  $ hackmyagent attack https://api.example.com --payload-file custom.json
  $ hackmyagent attack https://api.example.com --fail-on-vulnerable medium
  $ hackmyagent attack http://localhost:3010 --target-type mcp --category mcp-exploitation
  $ hackmyagent attack http://localhost:3020 --target-type a2a --category a2a-attack
  $ hackmyagent attack https://api.example.com --publish  Attack and publish results to registry`)
  .argument('[target]', 'API endpoint to test (or use --local for simulation)')
  .option('-i, --intensity <level>', 'Attack intensity: passive, active, aggressive', 'active')
  .option('-c, --category <categories>', 'Comma-separated categories to test')
  .option('--local', 'Run in local simulation mode (no actual API calls)')
  .option('-t, --target-type <type>', 'Target type: api, mcp, a2a, local', 'api')
  .option('--api-format <format>', 'API format: openai, anthropic, mcp-jsonrpc, a2a, custom', 'openai')
  .option('--model <model>', 'Model to test (for API targets)')
  .option('--system-prompt <prompt>', 'System prompt (for local testing)')
  .option('--mcp-tool <tool>', 'Default MCP tool name (for mcp targets)')
  .option('--a2a-sender <name>', 'A2A sender identity (for a2a targets)', 'attacker-agent')
  .option('--a2a-recipient <name>', 'A2A recipient identity (for a2a targets)', 'target-agent')
  .option('-H, --header <headers>', 'Headers in format "Key: Value" (can be used multiple times)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '30000')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '1000')
  .option('--stop-on-success', 'Stop after first successful attack')
  .option('--payload-file <path>', 'JSON file with custom attack payloads')
  .option('--fail-on-vulnerable [severity]', 'Exit code 1 if vulnerabilities found (optional: critical/high/medium/low)')
  .option('--json', 'Output as JSON (shorthand for --format json)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html', 'text')
  .option('-o, --output <file>', 'Write output to file')
  .option('-v, --verbose', 'Show detailed output for each payload')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-report', 'Post results to OpenA2A Registry')
  .option('--no-registry', 'Skip auto-publishing results to OpenA2A Registry')
  .option('--version-id <id>', 'Registry version ID to report against')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', process.env.REGISTRY_URL || 'https://api.oa2a.org')
  .option('--registry-key <key>', 'Registry API key (default: REGISTRY_API_KEY env)')
  .action(async (targetUrl: string | undefined, options: {
    intensity?: string;
    category?: string;
    local?: boolean;
    targetType?: string;
    apiFormat?: string;
    model?: string;
    systemPrompt?: string;
    mcpTool?: string;
    a2aSender?: string;
    a2aRecipient?: string;
    header?: string | string[];
    timeout?: string;
    delay?: string;
    stopOnSuccess?: boolean;
    payloadFile?: string;
    failOnVulnerable?: string | boolean;
    format?: string;
    output?: string;
    verbose?: boolean;
    publish?: boolean;
    registryReport?: boolean;
    registry?: boolean;
    versionId?: string;
    registryUrl?: string;
    registryKey?: string;
    json?: boolean;
  }) => {
    try {
      // Validate target
      if (!targetUrl && !options.local) {
        console.error('Error: Target URL required (or use --local for simulation)');
        process.exit(1);
      }

      // Validate intensity
      const validIntensities = ['passive', 'active', 'aggressive'];
      const intensity = (options.intensity || 'active') as AttackIntensity;
      if (!validIntensities.includes(intensity)) {
        console.error(`Error: Invalid intensity '${options.intensity}'. Use: ${validIntensities.join(', ')}`);
        process.exit(1);
      }

      // Parse categories
      let categories: AttackCategory[] | undefined;
      if (options.category) {
        categories = options.category.split(',').map(c => c.trim()) as AttackCategory[];
        for (const cat of categories) {
          if (!ATTACK_CATEGORY_NAMES.includes(cat)) {
            console.error(`Error: Invalid category '${cat}'. Use: ${ATTACK_CATEGORY_NAMES.join(', ')}`);
            process.exit(1);
          }
        }
      }

      // Parse headers
      const headers: Record<string, string> = {};
      if (options.header) {
        const headerList = Array.isArray(options.header) ? options.header : [options.header];
        for (const h of headerList) {
          const [key, ...valueParts] = h.split(':');
          if (key && valueParts.length > 0) {
            headers[key.trim()] = valueParts.join(':').trim();
          }
        }
      }

      // Determine target type
      let targetType: 'api' | 'mcp' | 'a2a' | 'local' = 'api';
      if (options.local) {
        targetType = 'local';
      } else if (options.targetType) {
        const validTypes = ['api', 'mcp', 'a2a', 'local'];
        if (!validTypes.includes(options.targetType)) {
          console.error(`Error: Invalid target type '${options.targetType}'. Use: ${validTypes.join(', ')}`);
          process.exit(1);
        }
        targetType = options.targetType as 'api' | 'mcp' | 'a2a' | 'local';
      }

      // Auto-detect api format from target type if not explicitly set
      let apiFormat = options.apiFormat || 'openai';
      if (targetType === 'mcp' && apiFormat === 'openai') {
        apiFormat = 'mcp-jsonrpc';
      } else if (targetType === 'a2a' && apiFormat === 'openai') {
        apiFormat = 'a2a';
      }

      // Build target
      // When --local is used, treat the argument as a directory path, not a URL
      let localPath: string | undefined;
      if (targetType === 'local' && targetUrl) {
        const path = require('path');
        const fs = require('fs');
        const resolved = path.resolve(targetUrl);
        if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          localPath = resolved;
        }
      }

      const target: AttackTarget = {
        url: localPath ? '' : (targetUrl || ''),
        type: targetType,
        localPath,
        headers: Object.keys(headers).length > 0 ? headers : undefined,
        apiFormat: apiFormat as 'openai' | 'anthropic' | 'mcp-jsonrpc' | 'a2a' | 'custom',
        model: options.model,
        systemPrompt: options.systemPrompt,
        mcpTool: options.mcpTool,
        a2aSender: options.a2aSender,
        a2aRecipient: options.a2aRecipient,
      };

      // Validate format (--json is shorthand for --format json)
      const validFormats = ['text', 'json', 'sarif', 'html'];
      const format = options.json ? 'json' : (options.format || 'text');
      if (!validFormats.includes(format)) {
        console.error(`Error: Invalid format '${format}'. Use: ${validFormats.join(', ')}`);
        process.exit(1);
      }

      // Load custom payloads from file
      let customPayloads: AttackPayload[] | undefined;
      if (options.payloadFile) {
        const filePath = require('path').resolve(options.payloadFile);
        if (!require('fs').existsSync(filePath)) {
          console.error(`Error: Payload file not found: ${filePath}`);
          process.exit(1);
        }
        const fileContent = require('fs').readFileSync(filePath, 'utf-8');
        customPayloads = parseCustomPayloads(fileContent);
      }

      // Show header for text output
      if (format === 'text') {
        console.log(`\nHackMyAgent Attack Mode`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        console.log(`Target: ${target.type === 'local' ? (localPath ? `Local Directory: ${localPath}` : 'Local Simulation') : targetUrl}`);
        console.log(`Intensity: ${intensity}`);
        if (customPayloads) {
          console.log(`Payloads: ${customPayloads.length} custom (from file)`);
        } else {
          console.log(`Categories: ${categories ? categories.join(', ') : 'all'}`);
        }
        console.log();
      }

      // Run attack
      const scanner = new AttackScanner();
      const report = await scanner.scan(target, {
        intensity,
        categories,
        customPayloads,
        timeout: parseInt(options.timeout || '30000', 10),
        delay: parseInt(options.delay || '1000', 10),
        stopOnSuccess: options.stopOnSuccess,
        verbose: options.verbose,
      });

      // Output results
      let output: string;
      switch (format) {
        case 'json':
          output = JSON.stringify(report, null, 2);
          break;
        case 'sarif':
          output = generateAttackSarif(report);
          break;
        case 'html':
          output = generateAttackHtmlReport(report);
          break;
        default: // text
          printAttackReport(report, options.verbose ?? false);
          output = '';
      }

      // Write output
      if (output) {
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          console.log(output);
        }
      }

      // Registry reporting: only when explicitly requested via --version-id (CI) or --registry-report
      const shouldReport = targetType !== 'local' && (options.versionId || options.registryReport);
      if (shouldReport) {
        try {
          const core = await import('./index');
          const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';

          if (options.versionId) {
            // Authenticated path: existing behavior (version-id + API key)
            const registryKey = options.registryKey || process.env.REGISTRY_API_KEY;
            if (!registryKey) {
              console.error('Error: --registry-key or REGISTRY_API_KEY env is required when using --version-id');
              process.exit(1);
            }
            const client = new core.RegistryClient({ registryUrl, apiKey: registryKey });
            const payload = core.buildAttackReport(options.versionId, report);
            await client.reportScanResult(payload);
            console.log(`Registry: attack results reported for version ${options.versionId}`);
          } else if (typeof core.buildCommunityAttackReport === 'function') {
            // Community path: request scan token, then submit results
            const client = new core.RegistryClient({ registryUrl, apiKey: '' });
            const packageName = target.url || targetUrl || 'unknown';
            const tokenResp = typeof client.requestScanToken === 'function'
              ? await client.requestScanToken(packageName)
              : null;
            const payload = core.buildCommunityAttackReport(packageName, report);
            const resp = typeof client.reportCommunityResult === 'function'
              ? await client.reportCommunityResult(payload, tokenResp?.scanToken)
              : { status: 'skipped' };
            if (resp.status === 'accepted') {
              console.log('Registry: attack results shared with OpenA2A community');
            }
          }
        } catch (_reportErr: any) {
          // Silently ignore registry errors - they are not relevant to local scan results
        }
      }

      // Publish: push attack results to registry when --publish is used
      if (options.publish && options.registry === false) {
        if (format === 'text') {
          console.log('\nPublish skipped: --no-registry flag is active.');
        }
      } else if (options.publish && targetType === 'local') {
        if (format === 'text') {
          console.log('\nPublish skipped: only available for live target scans.');
        }
      } else if (options.publish && targetType !== 'local') {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const regUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';
          const packageName = target.url || targetUrl || 'unknown';

          if (format === 'text') {
            console.log('\nPublishing results to registry...\n');
          }

          const publishData = {
            packageName,
            directory: process.cwd(),
            attackReport: report,
          };

          const publishResult = await publishScanResults(publishData, regUrl);
          if (format === 'text') {
            console.log(formatPublishOutput(publishResult, publishData, regUrl));
            console.log();
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          console.error(`\nFailed to publish to registry: ${msg}`);
          console.error('Scan results are still available locally.');
        }
      }

      // Exit with non-zero based on fail policy
      if (shouldFail(report, options.failOnVulnerable as FailPolicy)) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Attack report formatting
function printAttackReport(report: AttackReport, verbose: boolean): void {
  const riskColors: Record<AttackReport['riskRating'], string> = {
    'critical': colors.brightRed,
    'high': colors.red,
    'medium': colors.yellow,
    'low': colors.green,
    'secure': colors.green,
  };

  // Summary
  console.log(`Risk Score: ${riskColors[report.riskRating]}${report.riskScore}/100 (${report.riskRating.toUpperCase()})${RESET()}`);
  console.log(`Duration: ${report.duration}ms`);
  console.log();

  // Attack summary
  console.log(`Attacks: ${report.summary.total} total | ${colors.red}${report.summary.successful} successful${RESET()} | ${colors.green}${report.summary.blocked} blocked${RESET()} | ${report.summary.inconclusive} inconclusive`);
  console.log();

  // Category breakdown
  console.log(`Categories:`);
  for (const [cat, stats] of Object.entries(report.summary.byCategory)) {
    if (stats.total === 0) continue;
    const catInfo = ATTACK_CATEGORIES[cat as AttackCategory];
    const icon = stats.successful > 0 ? '[-]' : '[+]';
    console.log(`  ${icon} ${catInfo.name}: ${stats.successful}/${stats.total} successful`);
  }
  console.log();

  // Successful attacks
  const successful = report.results.filter(r => r.success);
  if (successful.length > 0) {
    console.log(`${colors.red}Successful Attacks:${RESET()}`);
    for (const r of successful) {
      const sevColor = r.payload.severity === 'critical' ? colors.brightRed :
                       r.payload.severity === 'high' ? colors.red :
                       r.payload.severity === 'medium' ? colors.yellow : colors.green;
      console.log(`  ${sevColor}[${r.payload.severity.toUpperCase()}]${RESET()} ${r.payload.id}: ${r.payload.name}`);
      if (verbose) {
        console.log(`       Evidence: ${r.evidence}`);
        console.log(`       Remediation: ${r.payload.remediation}`);
      }
    }
    console.log();
  }

  // Blocked attacks (only in verbose)
  if (verbose) {
    const blocked = report.results.filter(r => r.blocked);
    if (blocked.length > 0) {
      console.log(`${colors.green}Blocked Attacks (${blocked.length}):${RESET()}`);
      for (const r of blocked) {
        console.log(`  [+] ${r.payload.id}: ${r.payload.name}`);
      }
      console.log();
    }
  }

  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  // Inconclusive explanation (when there are inconclusive results)
  if (report.summary.inconclusive > 0) {
    console.log(`Note: ${report.summary.inconclusive} result(s) were inconclusive -- no clear success or block`);
    console.log(`indicators matched the simulated response.`);
    if (report.targetType === 'local') {
      console.log(`Run against a live endpoint (without --local) for active testing with real responses.`);
    }
    console.log();
  }

  if (!verbose) {
    console.log(`\nUse --verbose for detailed attack results.`);
  }
  if (report.intensity !== 'aggressive') {
    console.log(`Use --intensity aggressive for advanced attacks.`);
  }
  console.log();
}

// Generate SARIF output for attack results
function generateAttackSarif(report: AttackReport): string {
  const rules = report.results
    .filter(r => r.success)
    .map(r => ({
      id: r.payload.id,
      name: r.payload.name.replace(/\s+/g, ''),
      shortDescription: { text: r.payload.name },
      fullDescription: { text: r.payload.description },
      help: { text: r.payload.remediation },
      helpUri: `https://oasb.ai/attacks/${r.payload.id}`,
      defaultConfiguration: {
        level: r.payload.severity === 'critical' || r.payload.severity === 'high' ? 'error' as const :
               r.payload.severity === 'medium' ? 'warning' as const : 'note' as const,
      },
      properties: {
        'security-severity': r.payload.severity === 'critical' ? '9.0' :
                            r.payload.severity === 'high' ? '7.0' :
                            r.payload.severity === 'medium' ? '5.0' : '3.0',
        tags: ['security', 'ai-agent', r.payload.category],
      },
    }));

  const results = report.results
    .filter(r => r.success)
    .map(r => ({
      ruleId: r.payload.id,
      level: r.payload.severity === 'critical' || r.payload.severity === 'high' ? 'error' as const :
             r.payload.severity === 'medium' ? 'warning' as const : 'note' as const,
      message: { text: `${r.payload.name}: ${r.evidence}` },
    }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  }, null, 2);
}

// Generate HTML report for attack results
function generateAttackHtmlReport(report: AttackReport): string {
  // Risk grade based on score
  const getGrade = (score: number): { letter: string; color: string } => {
    if (score <= 10) return { letter: 'strong', color: '#22c55e' };
    if (score <= 25) return { letter: 'good', color: '#84cc16' };
    if (score <= 50) return { letter: 'moderate', color: '#eab308' };
    if (score <= 70) return { letter: 'improving', color: '#f97316' };
    return { letter: 'needs-attention', color: '#ef4444' };
  };
  const grade = getGrade(report.riskScore);

  const ratingColor: Record<AttackReport['riskRating'], string> = {
    'critical': '#ef4444',
    'high': '#f97316',
    'medium': '#eab308',
    'low': '#22c55e',
    'secure': '#22c55e',
  };

  const ratingBg: Record<AttackReport['riskRating'], string> = {
    'critical': 'rgba(239, 68, 68, 0.15)',
    'high': 'rgba(249, 115, 22, 0.15)',
    'medium': 'rgba(234, 179, 8, 0.15)',
    'low': 'rgba(34, 197, 94, 0.15)',
    'secure': 'rgba(34, 197, 94, 0.15)',
  };

  // SVG icons
  const icons = {
    sword: '<svg class="icon icon-sword" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 17.5L3 6V3h3l11.5 11.5"/><path d="M13 19l6-6"/><path d="M16 16l4 4"/><path d="M19 21l2-2"/></svg>',
    shield: '<svg class="icon icon-shield" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clip-rule="evenodd"/></svg>',
    check: '<svg class="icon icon-check" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>',
    x: '<svg class="icon icon-x" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>',
    warning: '<svg class="icon icon-warning" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>',
    print: '<svg class="icon icon-print" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5 4v3H4a2 2 0 00-2 2v3a2 2 0 002 2h1v2a2 2 0 002 2h6a2 2 0 002-2v-2h1a2 2 0 002-2V9a2 2 0 00-2-2h-1V4a2 2 0 00-2-2H7a2 2 0 00-2 2zm8 0H7v3h6V4zm0 8H7v4h6v-4z" clip-rule="evenodd"/></svg>',
  };

  // Category abbreviations
  const categoryAbbrev: Record<AttackCategory, string> = {
    'prompt-injection': 'PI',
    'jailbreak': 'JB',
    'data-exfiltration': 'DE',
    'capability-abuse': 'CA',
    'context-manipulation': 'CM',
    'mcp-exploitation': 'MCP',
    'a2a-attack': 'A2A',
    'memory-weaponization': 'MEM',
    'context-window': 'CTX',
    'supply-chain': 'SUP',
    'tool-shadow': 'SHADOW',
  };

  // Donut chart for attack results
  const donutRadius = 60;
  const donutStroke = 12;
  const donutCircumference = 2 * Math.PI * donutRadius;
  const total = report.summary.total || 1;
  const successPct = report.summary.successful / total;
  const blockedPct = report.summary.blocked / total;
  const inconclusivePct = report.summary.inconclusive / total;

  const successDash = donutCircumference * successPct;
  const blockedDash = donutCircumference * blockedPct;
  const inconclusiveDash = donutCircumference * inconclusivePct;

  // Calculate offsets for each segment
  const successOffset = 0;
  const blockedOffset = successDash;
  const inconclusiveOffset = successDash + blockedDash;

  const donutSvg = `
    <svg width="160" height="160" viewBox="0 0 160 160">
      <!-- Background circle -->
      <circle cx="80" cy="80" r="${donutRadius}" fill="none" stroke="#334155" stroke-width="${donutStroke}"/>
      <!-- Inconclusive segment (gray) -->
      ${inconclusivePct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#64748b" stroke-width="${donutStroke}"
        stroke-dasharray="${inconclusiveDash} ${donutCircumference}"
        stroke-dashoffset="${-inconclusiveOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Blocked segment (green) -->
      ${blockedPct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#22c55e" stroke-width="${donutStroke}"
        stroke-dasharray="${blockedDash} ${donutCircumference}"
        stroke-dashoffset="${-blockedOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Successful segment (red) -->
      ${successPct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#ef4444" stroke-width="${donutStroke}"
        stroke-dasharray="${successDash} ${donutCircumference}"
        stroke-dashoffset="${-successOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Center text -->
      <text x="80" y="75" text-anchor="middle" fill="#f1f5f9" font-size="24" font-weight="700">${report.summary.total}</text>
      <text x="80" y="95" text-anchor="middle" fill="#94a3b8" font-size="12">attacks</text>
    </svg>`;

  // Generate category breakdown rows
  const categoryRows = Object.entries(report.summary.byCategory)
    .filter(([_, stats]) => stats.total > 0)
    .map(([cat, stats]) => {
      const catInfo = ATTACK_CATEGORIES[cat as AttackCategory];
      const abbrev = categoryAbbrev[cat as AttackCategory];
      const successRate = stats.total > 0 ? Math.round((stats.successful / stats.total) * 100) : 0;
      const barColor = stats.successful === 0 ? '#22c55e' : successRate > 50 ? '#ef4444' : '#eab308';
      const statusIcon = stats.successful === 0 ? icons.check : icons.x;
      const statusClass = stats.successful === 0 ? 'status-pass' : 'status-fail';

      // Get results for this category
      const catResults = report.results.filter(r => r.payload.category === cat);

      const resultRows = catResults.map(r => {
        const resultIcon = r.success ? icons.x : r.blocked ? icons.check : icons.warning;
        const resultClass = r.success ? 'status-fail' : r.blocked ? 'status-pass' : 'status-warn';
        const sevColor = r.payload.severity === 'critical' ? '#ef4444' :
                        r.payload.severity === 'high' ? '#f97316' :
                        r.payload.severity === 'medium' ? '#eab308' : '#22c55e';
        return `
          <tr class="attack-row ${r.success ? 'failed' : ''}">
            <td class="status-cell"><span class="${resultClass}">${resultIcon}</span></td>
            <td class="id-cell"><code>${r.payload.id}</code></td>
            <td class="name-cell">${escapeHtml(r.payload.name)}</td>
            <td class="severity-cell"><span class="severity-badge" style="color: ${sevColor}; background: ${sevColor}20;">${r.payload.severity.toUpperCase()}</span></td>
            <td class="result-cell">${r.success ? '<span class="result-tag fail">Succeeded</span>' : r.blocked ? '<span class="result-tag pass">Blocked</span>' : '<span class="result-tag warn">Inconclusive</span>'}</td>
          </tr>`;
      }).join('');

      return `
        <div class="category" id="cat-${abbrev}">
          <div class="category-header" onclick="toggleCategory('${abbrev}')">
            <span class="category-abbrev">[${abbrev}]</span>
            <span class="category-icon ${statusClass}">${statusIcon}</span>
            <span class="category-name">${escapeHtml(catInfo.name)}</span>
            <div class="category-meta">
              <span class="category-score">${stats.successful}/${stats.total} successful</span>
              <div class="mini-bar"><div class="mini-fill" style="width: ${successRate}%; background: ${barColor};"></div></div>
              <span class="chevron">▼</span>
            </div>
          </div>
          <div class="category-content">
            <table class="attacks-table">
              <thead><tr><th></th><th>ID</th><th>Attack</th><th>Severity</th><th>Result</th></tr></thead>
              <tbody>${resultRows}</tbody>
            </table>
          </div>
        </div>`;
    }).join('');

  // Successful attacks detail section
  const successfulAttacks = report.results.filter(r => r.success);
  const successfulDetailsHtml = successfulAttacks.length > 0 ? successfulAttacks.map(r => {
    const sevColor = r.payload.severity === 'critical' ? '#ef4444' :
                    r.payload.severity === 'high' ? '#f97316' :
                    r.payload.severity === 'medium' ? '#eab308' : '#22c55e';
    return `
      <div class="attack-detail">
        <div class="attack-detail-header">
          <code class="attack-id">${r.payload.id}</code>
          <span class="attack-name">${escapeHtml(r.payload.name)}</span>
          <span class="severity-badge" style="color: ${sevColor}; background: ${sevColor}20;">${r.payload.severity.toUpperCase()}</span>
        </div>
        <div class="attack-detail-meta">
          ${r.payload.oasbControl ? `<span class="meta-tag">OASB ${r.payload.oasbControl}</span>` : ''}
          ${r.payload.cwe ? `<span class="meta-tag">CWE-${r.payload.cwe}</span>` : ''}
          <span class="meta-tag">${ATTACK_CATEGORIES[r.payload.category].name}</span>
        </div>
        <div class="attack-detail-body">
          <div class="detail-section">
            <strong>Description:</strong> ${escapeHtml(r.payload.description)}
          </div>
          <div class="detail-section evidence">
            <strong>Evidence:</strong> ${escapeHtml(r.evidence)}
          </div>
          <div class="detail-section remediation">
            <strong>Remediation:</strong> ${escapeHtml(r.payload.remediation)}
          </div>
        </div>
      </div>`;
  }).join('') : '<div class="no-attacks">No successful attacks detected.</div>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HackMyAgent Attack Report | ${report.riskRating.toUpperCase()}</title>
  <style>
    :root {
      --bg-primary: #0a0f1a;
      --bg-secondary: #111827;
      --bg-tertiary: #1f2937;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border: #334155;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
      font-size: 14px;
    }
    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding: 1.5rem 2rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .header-left h1 {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .header-left .meta { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem; }
    .header-icon { display: inline-flex; margin-right: 0.5rem; }
    .header-icon .icon { width: 24px; height: 24px; color: var(--danger); }
    .header-right { display: flex; align-items: center; gap: 1rem; }
    .rating-badge {
      display: inline-block;
      padding: 0.375rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.875rem;
      background: ${ratingBg[report.riskRating]};
      color: ${ratingColor[report.riskRating]};
      border: 1px solid ${ratingColor[report.riskRating]}40;
    }
    .intensity-tag {
      display: inline-block;
      padding: 0.375rem 1rem;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 600;
      text-transform: capitalize;
    }

    /* SVG Icons */
    .icon { width: 16px; height: 16px; display: inline-block; vertical-align: middle; }
    .status-pass { color: var(--success); }
    .status-fail { color: var(--danger); }
    .status-warn { color: var(--warning); }
    .category-icon { display: flex; align-items: center; }
    .category-icon .icon { width: 18px; height: 18px; }
    .footer-btn .icon { width: 14px; height: 14px; margin-right: 0.375rem; }

    /* Dashboard grid */
    .dashboard {
      display: grid;
      grid-template-columns: 280px 200px 1fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 1200px) {
      .dashboard { grid-template-columns: 1fr 1fr; }
      .summary-section { grid-column: span 2; }
    }
    @media (max-width: 768px) {
      .dashboard { grid-template-columns: 1fr; }
      .summary-section { grid-column: span 1; }
    }

    /* Risk Score card */
    .score-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
    }
    .score-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.25rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .score-grade {
      width: 72px;
      height: 72px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; text-align: center; line-height: 1.2; }
    .score-main { flex: 1; }
    .score-pct { font-size: 2rem; font-weight: 700; color: var(--text-primary); line-height: 1; }
    .score-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }

    .score-stats { margin-top: 1rem; }
    .stat-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
    }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--text-secondary); font-size: 0.85rem; }
    .stat-value { font-weight: 600; }
    .stat-value.danger { color: var(--danger); }
    .stat-value.success { color: var(--success); }
    .stat-value.muted { color: var(--text-muted); }

    /* Donut chart section */
    .donut-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .donut-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
      width: 100%;
    }
    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      margin-top: 1rem;
      width: 100%;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
      color: var(--text-secondary);
    }
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }

    /* Summary section */
    .summary-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .summary-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .severity-breakdown {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .severity-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
    }
    .severity-count { font-size: 1.25rem; font-weight: 700; }
    .severity-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }

    /* Categories */
    .categories-section {
      margin-bottom: 2rem;
    }
    .categories-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .categories-header h2 { font-size: 1.1rem; }
    .expand-all {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .expand-all:hover { background: var(--border); }

    .category {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 0.75rem;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .category-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.25rem;
      cursor: pointer;
      transition: background 0.15s;
    }
    .category-header:hover { background: var(--bg-tertiary); }
    .category-abbrev {
      font-family: monospace;
      font-size: 0.85rem;
      color: var(--accent);
      font-weight: 600;
    }
    .category-icon { font-size: 1.1rem; }
    .category-name { flex: 1; font-weight: 500; }
    .category-meta { display: flex; align-items: center; gap: 0.75rem; }
    .category-score { color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; }
    .mini-bar { width: 60px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .mini-fill { height: 100%; border-radius: 3px; }
    .chevron {
      color: var(--text-muted);
      font-size: 0.7rem;
      transition: transform 0.2s;
      margin-left: 0.5rem;
    }
    .category.collapsed .chevron { transform: rotate(-90deg); }
    .category.collapsed .category-content { display: none; }

    .category-content { border-top: 1px solid var(--border); }
    .attacks-table { width: 100%; border-collapse: collapse; }
    .attacks-table th {
      padding: 0.75rem 1rem;
      text-align: left;
      background: var(--bg-primary);
      color: var(--text-muted);
      font-weight: 500;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .attacks-table td {
      padding: 0.875rem 1rem;
      border-top: 1px solid var(--border);
      vertical-align: middle;
    }
    .status-cell { width: 40px; text-align: center; }
    .id-cell { width: 80px; }
    .id-cell code {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: var(--accent);
    }
    .name-cell { width: 40%; }
    .severity-cell { width: 80px; }
    .result-cell { width: 100px; }
    .attack-row.failed { background: rgba(239, 68, 68, 0.05); }

    .severity-badge {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .result-tag {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
    }
    .result-tag.pass { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .result-tag.fail { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    .result-tag.warn { background: rgba(234, 179, 8, 0.2); color: var(--warning); }

    /* Successful attacks detail */
    .details-section {
      margin-bottom: 2rem;
    }
    .details-section h2 {
      font-size: 1.1rem;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .details-section h2 .icon { color: var(--danger); }
    .attack-detail {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 1rem;
      border: 1px solid var(--border);
      border-left: 3px solid var(--danger);
      overflow: hidden;
    }
    .attack-detail-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 1rem 1.25rem;
      background: rgba(239, 68, 68, 0.05);
    }
    .attack-id {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.85rem;
      color: var(--danger);
    }
    .attack-name { flex: 1; font-weight: 500; }
    .attack-detail-meta {
      display: flex;
      gap: 0.5rem;
      padding: 0.75rem 1.25rem;
      background: var(--bg-tertiary);
      border-bottom: 1px solid var(--border);
    }
    .meta-tag {
      padding: 0.2rem 0.5rem;
      background: var(--bg-secondary);
      border-radius: 4px;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .attack-detail-body { padding: 1rem 1.25rem; }
    .detail-section {
      margin-bottom: 0.75rem;
      font-size: 0.9rem;
      color: var(--text-secondary);
    }
    .detail-section:last-child { margin-bottom: 0; }
    .detail-section strong { color: var(--text-primary); margin-right: 0.5rem; }
    .detail-section.evidence {
      padding: 0.75rem;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 6px;
      border-left: 3px solid var(--danger);
    }
    .detail-section.remediation {
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
      border-left: 3px solid var(--accent);
    }
    .no-attacks {
      padding: 2rem;
      text-align: center;
      color: var(--success);
      background: var(--bg-secondary);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    /* Footer */
    .footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 2rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .footer a { color: var(--accent); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .footer-actions { display: flex; gap: 1rem; }
    .footer-btn {
      display: flex;
      align-items: center;
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .footer-btn:hover { background: var(--border); }

    /* Print styles */
    @media print {
      body { background: white; color: black; padding: 1rem; }
      .container { max-width: 100%; }
      .header, .score-card, .donut-section, .summary-section, .category, .attack-detail, .footer {
        background: white;
        border: 1px solid #ddd;
        break-inside: avoid;
      }
      .category.collapsed .category-content { display: block !important; }
      .chevron, .expand-all, .footer-actions { display: none; }
      .category-header { cursor: default; }
      .attack-row.failed { background: #fff0f0; }
      :root {
        --bg-primary: white;
        --bg-secondary: white;
        --bg-tertiary: #f5f5f5;
        --text-primary: black;
        --text-secondary: #555;
        --text-muted: #888;
        --border: #ddd;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="header-left">
        <h1><span class="header-icon">${icons.sword}</span>HackMyAgent Attack Report</h1>
        <div class="meta">Target: ${escapeHtml(report.target || 'Local Simulation')} • ${new Date(report.endTime).toLocaleString()}</div>
      </div>
      <div class="header-right">
        <div class="rating-badge">${report.riskRating.toUpperCase()} RISK</div>
        <div class="intensity-tag">${report.intensity}</div>
      </div>
    </header>

    <div class="dashboard">
      <div class="score-card">
        <div class="score-header">
          <div class="score-grade" style="background: ${grade.color}20; border-color: ${grade.color};">
            <span class="grade-letter" style="color: ${grade.color};">${grade.letter}</span>
          </div>
          <div class="score-main">
            <div class="score-pct">${report.riskScore}/100</div>
            <div class="score-label">Risk Score</div>
          </div>
        </div>
        <div class="score-stats">
          <div class="stat-row">
            <span class="stat-label">Successful Attacks</span>
            <span class="stat-value danger">${report.summary.successful}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Blocked Attacks</span>
            <span class="stat-value success">${report.summary.blocked}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Inconclusive</span>
            <span class="stat-value muted">${report.summary.inconclusive}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Duration</span>
            <span class="stat-value">${report.duration}ms</span>
          </div>
        </div>
      </div>

      <div class="donut-section">
        <h3>Attack Results</h3>
        ${donutSvg}
        <div class="donut-legend">
          <div class="legend-item"><span class="legend-dot" style="background: #ef4444;"></span> Successful (${report.summary.successful})</div>
          <div class="legend-item"><span class="legend-dot" style="background: #22c55e;"></span> Blocked (${report.summary.blocked})</div>
          <div class="legend-item"><span class="legend-dot" style="background: #64748b;"></span> Inconclusive (${report.summary.inconclusive})</div>
        </div>
      </div>

      <div class="summary-section">
        <h3>Severity Breakdown (Successful Attacks)</h3>
        <div class="severity-breakdown">
          <div class="severity-item">
            <span class="severity-count" style="color: #ef4444;">${report.summary.bySeverity.critical || 0}</span>
            <span class="severity-label">Critical</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #f97316;">${report.summary.bySeverity.high || 0}</span>
            <span class="severity-label">High</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #eab308;">${report.summary.bySeverity.medium || 0}</span>
            <span class="severity-label">Medium</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #22c55e;">${report.summary.bySeverity.low || 0}</span>
            <span class="severity-label">Low</span>
          </div>
        </div>
      </div>
    </div>

    <div class="categories-section">
      <div class="categories-header">
        <h2>Category Breakdown</h2>
        <button class="expand-all" onclick="toggleAll()">Expand/Collapse All</button>
      </div>
      ${categoryRows}
    </div>

    <div class="details-section">
      <h2>${icons.x} Successful Attacks Detail</h2>
      ${successfulDetailsHtml}
    </div>

    <footer class="footer">
      <div>Generated by <a href="https://hackmyagent.com">HackMyAgent</a> v${VERSION} • <a href="https://oasb.ai/attacks">oasb.ai/attacks</a></div>
      <div class="footer-actions">
        <button class="footer-btn" onclick="window.print()">${icons.print} Print Report</button>
      </div>
    </footer>
  </div>

  <script>
    function toggleCategory(id) {
      const cat = document.getElementById('cat-' + id);
      cat.classList.toggle('collapsed');
    }
    function toggleAll() {
      const cats = document.querySelectorAll('.category');
      const allCollapsed = Array.from(cats).every(c => c.classList.contains('collapsed'));
      cats.forEach(c => {
        if (allCollapsed) {
          c.classList.remove('collapsed');
        } else {
          c.classList.add('collapsed');
        }
      });
    }
  </script>
</body>
</html>`;
}

// --- fix-all: Run all OpenClaw plugins to scan and remediate ---

import { createPlugin as createCredVaultPlugin } from './plugins/credvault';
import { createPlugin as createSecretlessPlugin } from './plugins/secretless';
import { createPlugin as createSigncryptPlugin } from './plugins/signcrypt';
import { createPlugin as createSkillguardPlugin } from './plugins/skillguard';
import { AIMCore } from '@opena2a/aim-core';
import type {
  Finding as PluginFinding,
  Remediation,
  OpenA2APlugin,
  Severity as PluginSeverity,
} from './plugins/core';

const PLUGIN_SEVERITY_DISPLAY: Record<PluginSeverity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
  info: { symbol: '[i]', color: () => colors.cyan },
};

program
  .command('fix-all')
  .description(`Run all OpenA2A security plugins to scan and auto-fix agent issues

Runs the full plugin suite in order:
  1. Credential Protection     — find hardcoded secrets, replace with env vars
  2. AI Visibility Protection  — block .env from AI tools, encrypt MCP keys
  3. File Signing              — sign skills and heartbeats with Ed25519
  4. Skill Safety Scanner      — detect dangerous patterns, pin hashes

Each plugin scans for findings, then auto-fixes what it can.
Dangerous patterns (reverse shells, exfil, etc.) require manual review.

Step 2 requires secretless-ai (npm install -g secretless-ai). If not
installed, the plugin reports this and continues with the remaining steps.

Use --with-aim to create a cryptographic identity for your agent.
This enables automatic file signing, audit logging, and trust scoring
so you don't need to manage keys or track files manually.

Exit code 1 if critical/high issues remain after fixing.

Examples:
  $ hackmyagent fix-all                     Scan and fix current directory
  $ hackmyagent fix-all ./my-agent          Scan specific directory
  $ hackmyagent fix-all --with-aim          Create identity + sign + audit (recommended)
  $ hackmyagent fix-all --dry-run           Preview fixes without applying
  $ hackmyagent fix-all --scan-only         Scan without fixing
  $ hackmyagent fix-all --json              JSON output for CI`)
  .argument('[directory]', 'Agent directory to scan (default: current directory)', '')
  .option('--dry-run', 'Preview fixes without applying them')
  .option('--scan-only', 'Only scan, do not fix')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('--with-aim', 'Create agent identity for automatic signing, audit logging, and trust scoring')
  .option('-v, --verbose', 'Show all findings including passed plugins')
  .action(
    async (
      directory: string,
      options: {
        dryRun?: boolean;
        scanOnly?: boolean;
        json?: boolean;
        withAim?: boolean;
        verbose?: boolean;
      }
    ) => {
      try {
        const path = require('path');
        const fs = require('fs');

        // Resolve target directory with symlink protection
        let targetDir: string;
        if (directory && directory !== '') {
          targetDir = path.isAbsolute(directory) ? directory : path.resolve(process.cwd(), directory);
        } else {
          targetDir = process.cwd();
        }

        // Resolve realpath atomically — eliminates TOCTOU between existence check and resolution
        let realTarget: string;
        try {
          realTarget = fs.realpathSync(targetDir);
        } catch {
          console.error(`Error: Directory not found: ${targetDir}`);
          process.exit(1);
        }

        // Verify resolved path is a directory (realpath already resolved any symlinks)
        const resolvedStat = fs.statSync(realTarget);
        if (!resolvedStat.isDirectory()) {
          console.error(`Error: Not a directory: ${realTarget}`);
          process.exit(1);
        }

        // Block path traversal via .. in relative paths (but allow absolute paths)
        if (!path.isAbsolute(directory) && directory && directory !== '') {
          const realCwd = fs.realpathSync(process.cwd());
          const relative = path.relative(realCwd, realTarget);
          if (relative.startsWith('..')) {
            console.error(`Error: Target directory must not traverse above current working directory. Use an absolute path instead.`);
            process.exit(1);
          }
        }
        targetDir = realTarget;

        // Initialize AIM Core if requested
        let aimCore: AIMCore | undefined;
        if (options.withAim) {
          aimCore = new AIMCore({
            agentName: path.basename(targetDir),
            dataDir: path.join(targetDir, '.opena2a', 'aim'),
          });
        }

        // Create and initialize plugins in execution order
        // 1. CredVault finds hardcoded secrets, replaces with ${VAR}
        // 2. Secretless blocks .env from AI visibility (completes the credential lifecycle)
        // 3. SignCrypt signs skill and heartbeat files
        // 4. SkillGuard pins hashes last so they reflect the final file state
        const pluginFactories: Array<{ name: string; create: () => OpenA2APlugin }> = [
          { name: 'Credential Protection', create: createCredVaultPlugin },
          { name: 'AI Visibility Protection', create: createSecretlessPlugin },
          { name: 'File Signing', create: createSigncryptPlugin },
          { name: 'Skill Safety Scanner', create: createSkillguardPlugin },
        ];

        const plugins: Array<{ name: string; plugin: OpenA2APlugin }> = [];
        for (const factory of pluginFactories) {
          const plugin = factory.create();
          await plugin.init(aimCore ? { aimCore } : undefined);
          plugins.push({ name: factory.name, plugin });
        }

        if (!options.json) {
          console.log(`\n  OpenA2A Fix-All Security Report`);
          console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

          if (options.dryRun) {
            console.log(`Scanning ${targetDir} (dry-run -- previewing fixes)...\n`);
          } else if (options.scanOnly) {
            console.log(`Scanning ${targetDir} (scan-only -- no fixes applied)...\n`);
          } else {
            console.log(`Scanning and fixing ${targetDir}...\n`);
          }
        }

        // Aggregate results from all plugins
        interface PluginResult {
          name: string;
          findings: PluginFinding[];
          remediations: Remediation[];
        }

        const results: PluginResult[] = [];
        let allFindings: PluginFinding[] = [];
        let allRemediations: Remediation[] = [];
        let pluginErrors = 0;

        for (const { name, plugin } of plugins) {
          if (!options.json) {
            console.log(`${colors.cyan}> ${name}${RESET()}`);
          }

          try {
            // Scan
            const findings = await plugin.scan(targetDir);

            let remediations: Remediation[] = [];
            if (!options.scanOnly && findings.length > 0) {
              remediations = await plugin.fix(targetDir, {
                dryRun: options.dryRun ?? false,
              });
            }

            results.push({ name, findings, remediations });
            allFindings.push(...findings);
            allRemediations.push(...remediations);

            if (!options.json) {
              if (findings.length === 0) {
                console.log(`  ${colors.green}[+] No issues found${RESET()}`);
              } else {
                console.log(`  Found ${findings.length} issue(s)`);
                if (remediations.length > 0) {
                  console.log(
                    `  ${colors.green}[+] Fixed ${remediations.length}${RESET()}`
                  );
                }
              }
              console.log();
            }
          } catch (pluginErr) {
            // Isolate plugin errors — one failing plugin should not crash the entire run
            pluginErrors++;
            results.push({ name, findings: [], remediations: [] });
            if (!options.json) {
              console.log(`  ${colors.brightRed}[!!] Plugin error: ${pluginErr instanceof Error ? pluginErr.message : String(pluginErr)}${RESET()}`);
              if (pluginErr instanceof Error && pluginErr.stack) {
                console.error(pluginErr.stack);
              }
              console.log();
            }
          }
        }

        // JSON output
        if (options.json) {
          const unfixed = allFindings.filter(
            (f) => !allRemediations.some((r) => r.findingId === f.id)
          );
          const jsonOutput = {
            target: targetDir,
            mode: options.dryRun ? 'dry-run' : options.scanOnly ? 'scan-only' : 'fix',
            aimEnabled: !!aimCore,
            totalFindings: allFindings.length,
            totalFixed: allRemediations.length,
            remainingIssues: unfixed.length,
            pluginErrors,
            scanComplete: pluginErrors === 0,
            plugins: results.map((r) => ({
              name: r.name,
              findings: r.findings,
              remediations: r.remediations,
            })),
          };
          writeJsonStdout(jsonOutput);
          if (pluginErrors > 0) process.exit(2);
          return;
        }

        // Summary
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`\nFindings: ${allFindings.length} total | ${allRemediations.length} fixed\n`);

        // Show remaining issues (not auto-fixed)
        const fixedIds = new Set(allRemediations.map((r) => r.findingId));
        const remainingFindings = allFindings.filter((f) => !fixedIds.has(f.id) || !f.autoFixable);

        if (remainingFindings.length > 0) {
          console.log(`${colors.red}Remaining Issues (require manual review):${RESET()}\n`);

          for (const finding of remainingFindings) {
            const display = PLUGIN_SEVERITY_DISPLAY[finding.severity];
            console.log(
              `${display.color()}${display.symbol} [${finding.id}] ${finding.severity.toUpperCase()}${RESET()}`
            );
            console.log(`   ${finding.title}`);
            console.log(`   ${finding.description}`);
            if (finding.filePath) {
              console.log(`   File: ${finding.filePath}`);
            }
            console.log();
          }
        }

        // Show remediations applied
        if (allRemediations.length > 0 && !options.scanOnly) {
          const label = options.dryRun ? 'Fixes Available (dry-run):' : 'Fixes Applied:';
          console.log(`${colors.green}[+] ${label}${RESET()}\n`);

          for (const remediation of allRemediations) {
            console.log(`  ${colors.green}[+]${RESET()} [${remediation.findingId}] ${remediation.description}`);
            if (remediation.filesModified.length > 0 && options.verbose) {
              for (const file of remediation.filesModified) {
                console.log(`     ${colors.cyan}→${RESET()} ${file}`);
              }
            }
          }
          console.log();

          if (!options.dryRun) {
            console.log(
              `${colors.cyan}Note:${RESET()} Plugin data stored in ${targetDir}/.opena2a/`
            );
            console.log(
              `      Uninstall with: hackmyagent fix-all ${directory || '.'} --uninstall\n`
            );
          }
        }

        // All clear message
        if (allFindings.length === 0) {
          console.log(`${colors.green}[+] No security issues found. Agent looks good.${RESET()}\n`);
        }

        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`Run '${CLI_PREFIX} secure' for a full hardening scan.\n`);

        // Warn if scan is incomplete due to plugin errors
        if (pluginErrors > 0) {
          console.log(`\n${colors.brightRed}[!!] Note: ${pluginErrors} plugin(s) failed -- scan results are incomplete${RESET()}`);
          console.log(`     Re-run with --verbose for details.\n`);
        }

        // Exit with non-zero if critical/high issues remain or scan is incomplete
        if (pluginErrors > 0) {
          process.exit(2); // Exit 2 = partial/incomplete scan
        }
        const criticalOrHigh = remainingFindings.filter(
          (f) => f.severity === 'critical' || f.severity === 'high'
        );
        if (criticalOrHigh.length > 0) {
          process.exit(1);
        }
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        process.exit(1);
      }
    }
  );

// MCP Server command
program
  .command('mcp-serve')
  .description('Run HackMyAgent as an MCP server (stdio transport)')
  .action(async () => {
    try {
      const { startMcpServer } = await import('./mcp-server');
      await startMcpServer();
    } catch (error) {
      console.error(`Error starting MCP server: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

// Init MCP command
program
  .command('init-mcp')
  .description(`Add HackMyAgent as an MCP server to your AI coding tool

Detects your IDE (Claude Code, Cursor, VS Code) and configures
HackMyAgent as an MCP server for LLM-powered security analysis.

Once configured, ask your AI assistant:
  "Run a deep security scan on this project"

Examples:
  $ hackmyagent init-mcp
  $ hackmyagent init-mcp --tool cursor
  $ hackmyagent init-mcp /path/to/project`)
  .argument('[directory]', 'Project directory (defaults to current directory)', '.')
  .option('-t, --tool <name>', 'Force specific tool: claude, cursor, vscode')
  .action(async (directory: string, options: { tool?: string }) => {
    try {
      const targetDir = require("path").resolve(directory);
      const { initMcp } = await import('./init-mcp');
      const result = initMcp(targetDir, options.tool);

      if (!result.created) {
        console.log(`\n  HackMyAgent MCP server already configured in ${result.configPath}\n`);
        return;
      }

      console.log(`\n  Detected: ${result.tool}\n`);
      console.log(`  Added HackMyAgent MCP server to ${result.configPath}\n`);
      console.log(`  Available tools in ${result.tool}:`);
      console.log(`    hackmyagent_scan       — 202 checks + structural analysis`);
      console.log(`    hackmyagent_deep_scan  — Full analysis with LLM reasoning`);
      console.log(`    hackmyagent_analyze_file — Analyze a single file`);
      console.log(`    hackmyagent_benchmark  — OASB-1 compliance assessment\n`);
      console.log(`  Try: "Run a deep security scan on this project"\n`);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

function levelColor(level: SoulLevel): string {
  switch (level) {
    case 'hardened': return colors.green;
    case 'standard': return colors.green;
    case 'developing': return colors.yellow;
    case 'initial': return colors.cyan;
    case 'not-started': return colors.reset;
  }
}

function levelLabel(level: SoulLevel): string {
  switch (level) {
    case 'hardened': return 'Hardened';
    case 'standard': return 'Standard';
    case 'developing': return 'Developing';
    case 'initial': return 'Initial';
    case 'not-started': return 'Not Started';
  }
}

/**
 * Detect how the CLI was invoked to suggest correct command prefix.
 */
function getCommandPrefix(): string {
  const execPath = process.argv[1] || '';
  if (execPath.includes('npx') || execPath.includes('.npm/_npx') ||
      execPath.includes('node_modules/.bin')) {
    return 'npx hackmyagent';
  }
  return 'hackmyagent';
}

// Domain percentage bar for text output
function domainBar(pct: number): string {
  if (pct >= 80) return colors.green;
  if (pct >= 60) return colors.yellow;
  if (pct >= 40) return colors.yellow;
  return colors.red;
}

program
  .command('scan-soul')
  .description(`Scan behavioral governance coverage

Analyzes SOUL.md (or equivalent governance file) for coverage
across 9 behavioral governance domains with 72 security controls.

Searches for governance files in priority order:
  SOUL.md > system-prompt.md > SYSTEM_PROMPT.md > .cursorrules
  > .github/copilot-instructions.md > CLAUDE.md > .clinerules
  > instructions.md > constitution.md > agent-config.yaml

Agent profiles filter domains by agent purpose:
  conversational:  Injection, Hardcoded, Honesty, Harm Avoidance
  code-assistant:  + Trust, Data
  tool-agent:      + Capability, Oversight
  autonomous:      + Agentic Safety
  orchestrator:    All 9 domains

Maturity levels:
  Hardened (80+), Standard (60-79), Developing (40-59),
  Initial (1-39), Not Started (0)

Examples:
  $ hackmyagent scan-soul                    Scan current directory
  $ hackmyagent scan-soul ./my-agent         Scan specific directory
  $ hackmyagent scan-soul --json             Machine-readable output
  $ hackmyagent scan-soul --verbose          Show all controls
  $ hackmyagent scan-soul --profile conversational  Override profile
  $ hackmyagent scan-soul --deep             Enable LLM semantic analysis
  $ hackmyagent scan-soul ./my-agent --publish  Scan and publish results to registry`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show individual control results')
  .option('--tier <tier>', 'Override agent tier detection (BASIC, TOOL-USING, AGENTIC, MULTI-AGENT)')
  .option('--profile <profile>', 'Override agent profile (conversational, code-assistant, tool-agent, autonomous, orchestrator, custom)')
  .option('--fail-below <score>', 'Exit 1 if score below threshold (0-100)')
  .option('--deep', 'Enable LLM semantic analysis for ambiguous controls (requires claude CLI or ANTHROPIC_API_KEY)')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', process.env.REGISTRY_URL || 'https://api.oa2a.org')
  .option('--contribute', 'Share anonymized scan findings with OpenA2A Registry (overrides config)')
  .option('--no-contribute', 'Do not share findings for this scan (overrides config)')
  .option('--ci', 'CI mode: suppress interactive prompts, exit non-zero on findings')
  .action(async (directory: string, options: { json?: boolean; verbose?: boolean; tier?: string; profile?: string; failBelow?: string; deep?: boolean; publish?: boolean; registryUrl?: string; contribute?: boolean; ci?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      // CI mode: force non-interactive defaults
      if (options.ci) {
        if (options.contribute === undefined) options.contribute = false;
      }

      if (!require('fs').existsSync(targetDir)) {
        process.stderr.write(`Error: Directory '${targetDir}' does not exist.\n`);
        process.exit(1);
      }

      const prefix = getCommandPrefix();
      const scanner = new SoulScanner();
      const soulScanStartMs = Date.now();
      const result = await scanner.scanSoul(targetDir, {
        verbose: options.verbose,
        tier: options.tier,
        profile: options.profile,
        deepAnalysis: options.deep,
      });
      const soulScanDurationMs = Date.now() - soulScanStartMs;

      // JSON output
      if (options.json) {
        // Run publish in JSON mode and include result in output
        let publishStatus: Record<string, unknown> | undefined;
        if (options.publish) {
          try {
            const { publishScanResults } = await import('./registry/publish');
            const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const publishData = {
                packageName,
                packageVersion: resolvePackageVersion(targetDir) ?? undefined,
                directory: targetDir,
                soulResult: result,
              };
              const publishResult = await publishScanResults(publishData, registryUrl);
              publishStatus = { ...publishResult, registryUrl };
            } else {
              publishStatus = { success: false, error: 'Could not determine package name' };
            }
          } catch (publishErr: unknown) {
            const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
            publishStatus = { success: false, error: msg };
          }
        }

        const jsonOutput = publishStatus ? { ...result, publish: publishStatus } : result;
        writeJsonStdout(jsonOutput);
        // Check fail threshold
        if (options.failBelow) {
          const threshold = parseInt(options.failBelow, 10);
          if (!isNaN(threshold) && result.score < threshold) {
            process.exit(1);
          }
        }
        await handleSoulContribution(options.contribute, targetDir, result, soulScanDurationMs, options.registryUrl, 'json');
        return;
      }

      // Text output
      process.stdout.write('\nOASB v2 Behavioral Governance Scan\n');
      process.stdout.write('----------------------------------------------------\n\n');

      if (result.file) {
        process.stdout.write(`File: ${result.file} (${result.fileSize.toLocaleString()} chars)\n`);
      } else {
        process.stdout.write(`File: ${colors.red}No governance file found${colors.reset}\n`);
        process.stdout.write(`  Searched: ${['SOUL.md', 'system-prompt.md', 'CLAUDE.md', '...'].join(', ')}\n`);
      }

      const tierLabel = result.tierForced ? `${result.agentTier} (--tier flag)` : `${result.agentTier} (auto-detected)`;
      const profileLabel = result.profileForced ? `${result.agentProfile} (--profile flag)` : `${result.agentProfile} (auto-detected)`;
      process.stdout.write(`Agent Tier: ${tierLabel}\n`);
      process.stdout.write(`Agent Profile: ${profileLabel}\n`);
      if (result.skippedDomains.length > 0) {
        process.stdout.write(`Skipped Domains: ${result.skippedDomains.join(', ')}\n`);
      }
      process.stdout.write('\n');

      process.stdout.write('Domain Scores:\n');

      for (const domain of result.domains) {
        if (domain.skippedByProfile) {
          if (options.verbose) {
            const label = (domain.domain + ':').padEnd(26);
            process.stdout.write(`  ${label}${colors.reset}--  (skipped by profile)${colors.reset}\n`);
          }
          continue;
        }
        if (domain.skippedByTier) {
          const label = (domain.domain + ':').padEnd(26);
          process.stdout.write(`  ${label}${colors.reset}--  (not applicable at ${result.agentTier} tier)${colors.reset}\n`);
          continue;
        }
        const pctColor = domainBar(domain.percentage);
        const label = (domain.domain + ':').padEnd(26);
        process.stdout.write(`  ${label}${pctColor}${domain.passed}/${domain.total}  (${domain.percentage}%)${colors.reset}\n`);

        // Verbose: show individual controls
        if (options.verbose) {
          for (const ctrl of domain.controls) {
            const status = ctrl.passed
              ? `${colors.green}PASS${colors.reset}`
              : `${colors.red}FAIL${colors.reset}`;
            process.stdout.write(`    ${ctrl.id}: ${status}  ${ctrl.name}\n`);
          }
        }
      }

      process.stdout.write('\n');

      // Score and level (progress-oriented)
      const lc = levelColor(result.level);
      process.stdout.write(`Governance Score: ${lc}${result.score}/100 [${levelLabel(result.level)}]${colors.reset}\n`);

      // Conformance level
      if (result.conformance === 'none') {
        process.stdout.write(`Conformance: ${colors.red}NONE${colors.reset} -- critical control missing (${result.criticalMissing.join(', ')})\n`);
      } else {
        process.stdout.write(`Conformance: ${result.conformance.toUpperCase()}\n`);
      }

      if (result.criticalFloor) {
        process.stdout.write(`${colors.yellow}Critical Floor: APPLIED${colors.reset} (${result.criticalMissing.join(', ')} missing)\n`);
      }

      // Deep analysis summary
      if (result.deepAnalysisAvailable === false) {
        process.stdout.write(`${colors.yellow}Deep Analysis: unavailable${colors.reset} -- set ANTHROPIC_API_KEY or install the claude CLI\n`);
      } else if (result.deepAnalysisResults && result.deepAnalysisResults.length > 0) {
        const llmUpgraded = result.deepAnalysisResults.filter((e) => e.llmPassed).length;
        process.stdout.write(`Deep Analysis: ${llmUpgraded} control${llmUpgraded === 1 ? '' : 's'} upgraded by LLM semantic analysis\n`);
      }

      // Path forward (recovery-oriented, not punitive)
      const missing = result.totalControls - result.totalPassed;
      if (missing > 0) {
        const recoverable = Math.min(100 - result.score, 100);
        process.stdout.write(`\n  Path forward: +${recoverable} recoverable by addressing ${missing} control${missing === 1 ? '' : 's'}`);
        process.stdout.write(`\n  Run '${colors.cyan}${prefix} harden-soul${colors.reset}' to remediate.\n`);
      } else {
        process.stdout.write(`\n${colors.green}All ${result.totalControls} governance controls covered.${colors.reset}\n`);
      }

      process.stdout.write('\n');

      // Publish: push SOUL results to registry when --publish is used
      if (options.publish) {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const registryUrl = options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org';
          const packageName = resolvePackageName(targetDir);

          if (!packageName) {
            process.stderr.write('Could not determine package name. Publish requires a package.json with a name field.\n');
          } else {
            if (!options.json) {
              process.stdout.write('Publishing results to registry...\n\n');
            }

            const publishData = {
              packageName,
              packageVersion: resolvePackageVersion(targetDir) ?? undefined,
              directory: targetDir,
              soulResult: result,
            };

            const publishResult = await publishScanResults(publishData, registryUrl);
            if (!options.json) {
              process.stdout.write(formatPublishOutput(publishResult, publishData, registryUrl) + '\n\n');
            }
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          process.stderr.write(`Failed to publish to registry: ${msg}\n`);
          process.stderr.write('Scan results are still available locally.\n');
        }
      }

      // Community contribution: share anonymized findings with OpenA2A Registry
      const soulFormat = options.json ? 'json' : 'text';
      await handleSoulContribution(options.contribute, targetDir, result, soulScanDurationMs, options.registryUrl, soulFormat);

      // In CI mode, exit non-zero if any controls failed
      if (options.ci) {
        const failedControls = result.domains.flatMap(d => d.controls).filter(c => !c.passed);
        if (failedControls.length > 0) {
          process.exit(1);
        }
      }

      // Check fail threshold
      if (options.failBelow) {
        const threshold = parseInt(options.failBelow, 10);
        if (!isNaN(threshold) && result.score < threshold) {
          process.stderr.write(`Score ${result.score} is below threshold ${threshold}\n`);
          process.exit(1);
        }
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

program
  .command('harden-soul')
  .description(`Generate or update SOUL.md with missing governance sections

Runs scan-soul internally to identify missing controls, then generates
template content for each missing domain. Existing content is preserved.
Supports iterative hardening: if a domain heading exists but controls
fail within it, appends targeted remediation for those controls.

Modes:
  Default:    Append missing sections to SOUL.md (or create it)
  --dry-run:  Preview what would be added without modifying files

Examples:
  $ hackmyagent harden-soul                  Add missing sections
  $ hackmyagent harden-soul --dry-run        Preview changes
  $ hackmyagent harden-soul ./my-agent       Target specific directory
  $ hackmyagent harden-soul --json           Machine-readable output`)
  .argument('[directory]', 'Directory to harden (defaults to current directory)', '.')
  .option('--dry-run', 'Preview changes without modifying files')
  .option('--profile <profile>', 'Override agent profile (conversational, code-assistant, tool-agent, autonomous, orchestrator, custom)')
  .option('--json', 'Output as JSON')
  .action(async (directory: string, options: { dryRun?: boolean; profile?: string; json?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      if (!require('fs').existsSync(targetDir)) {
        process.stderr.write(`Error: Directory '${targetDir}' does not exist.\n`);
        process.exit(1);
      }

      const prefix = getCommandPrefix();
      const scanner = new SoulScanner();
      const result = await scanner.hardenSoul(targetDir, { dryRun: options.dryRun, profile: options.profile });

      // JSON output
      if (options.json) {
        // Exclude full content from JSON to keep it concise
        const jsonResult = {
          file: result.file,
          sectionsAdded: result.sectionsAdded,
          controlsAdded: result.controlsAdded,
          dryRun: result.dryRun,
          existedBefore: result.existedBefore,
        };
        writeJsonStdout(jsonResult);
        return;
      }

      // Text output
      if (result.sectionsAdded.length === 0) {
        process.stdout.write(`\n${colors.green}All governance domains already have sections in ${result.file}.${colors.reset}\n`);
        process.stdout.write(`Run '${prefix} scan-soul --verbose' to see individual control coverage.\n\n`);
        return;
      }

      if (result.dryRun) {
        process.stdout.write('\nHarden SOUL (dry-run)\n');
        process.stdout.write('----------------------------------------------------\n\n');
        process.stdout.write(`Target: ${result.file}`);
        if (result.existedBefore) {
          process.stdout.write(' (append)\n');
        } else {
          process.stdout.write(' (create)\n');
        }
        process.stdout.write(`Sections to add: ${result.sectionsAdded.length}\n`);
        process.stdout.write(`Controls covered: +${result.controlsAdded}\n\n`);

        process.stdout.write('Sections:\n');
        for (const section of result.sectionsAdded) {
          process.stdout.write(`  ${colors.cyan}+${colors.reset} ${section}\n`);
        }

        process.stdout.write(`\nRun without --dry-run to apply changes.\n\n`);
      } else {
        process.stdout.write('\nHarden SOUL\n');
        process.stdout.write('----------------------------------------------------\n\n');

        if (result.existedBefore) {
          process.stdout.write(`Updated: ${result.file}\n`);
        } else {
          process.stdout.write(`Created: ${result.file}\n`);
        }

        process.stdout.write(`Added ${result.sectionsAdded.length} section${result.sectionsAdded.length === 1 ? '' : 's'}:\n`);
        for (const section of result.sectionsAdded) {
          process.stdout.write(`  ${colors.green}+${colors.reset} ${section}\n`);
        }
        process.stdout.write(`Controls covered: +${result.controlsAdded}\n\n`);

        process.stdout.write(`Run '${colors.cyan}${prefix} scan-soul${colors.reset}' to verify coverage.\n\n`);
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// trust — Trust verification via OpenA2A Registry (powered by ai-trust)
// ---------------------------------------------------------------------------

const REGISTRY_DEFAULT_URL = 'https://api.oa2a.org';

interface TrustAnswer {
  packageId?: string;
  name: string;
  type?: string;
  packageType?: string;
  trustLevel: number;
  trustScore: number;
  verdict: string;
  scanStatus?: string;
  communityScans?: number;
  cveCount?: number;
  recommendation?: string;
  dependencies?: {
    direct?: number;
    transitive?: number;
    totalDeps: number;
    vulnerableDeps: number;
    minTrustLevel: number;
    minTrustScore: number;
    maxDepth: number;
    riskSummary?: { blocked: number; warning: number; safe: number };
  };
  found: boolean;
}

interface TrustBatchResponse {
  results: TrustAnswer[];
  total: number;
  queriedAt: string;
}

async function trustCheck(name: string, registryUrl: string, type?: string): Promise<TrustAnswer> {
  const params = new URLSearchParams({ name, includeProfile: 'true', includeDeps: 'true' });
  if (type) params.set('type', type);

  const url = `${registryUrl}/api/v1/trust/query?${params.toString()}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'Accept': 'application/json', 'User-Agent': `hackmyagent/${VERSION}` },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`Package "${name}" not found in the OpenA2A Registry.`);
    }
    const body = await res.text();
    throw new Error(`Registry API returned ${res.status}: ${body}`);
  }

  const data = (await res.json()) as TrustAnswer;
  data.found = !!data.packageId;
  return data;
}

async function trustBatch(
  packages: Array<{ name: string; type?: string }>,
  registryUrl: string
): Promise<{ results: TrustAnswer[]; meta: { total: number; found: number; notFound: number } }> {
  const url = `${registryUrl}/api/v1/trust/batch`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': `hackmyagent/${VERSION}`,
    },
    body: JSON.stringify({ packages }),
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error('Registry batch endpoint not found. The registry may be unavailable.');
    }
    const body = await res.text();
    throw new Error(`Registry API returned ${res.status}: ${body}`);
  }

  const raw = (await res.json()) as TrustBatchResponse;
  const NULL_UUID = '00000000-0000-0000-0000-000000000000';
  for (const r of raw.results) {
    r.found = !!r.packageId && r.packageId !== NULL_UUID;
  }
  const found = raw.results.filter((r) => r.found).length;
  return {
    results: raw.results,
    meta: { total: raw.total, found, notFound: raw.total - found },
  };
}

function trustLevelLabel(level: number): string {
  switch (level) {
    case 0: return 'Blocked';
    case 1: return 'Warning';
    case 2: return 'Listed';
    case 3: return 'Scanned';
    case 4: return 'Verified';
    default: return `Unknown (${level})`;
  }
}

function trustLevelColor(level: number): string {
  if (level >= 3) return colors.green;
  if (level >= 1) return colors.yellow;
  return colors.red;
}

function trustVerdictColor(verdict: string): string {
  switch (verdict) {
    case 'safe': return colors.green;
    case 'warning': return colors.yellow;
    case 'blocked': return colors.red;
    default: return colors.dim;
  }
}

function formatTrustCheck(answer: TrustAnswer): string {
  if (!answer.found) {
    return [
      '',
      `  ${answer.name}`,
      `  ${colors.dim}Type: ${answer.packageType || 'unknown'}${colors.reset}`,
      `  ${colors.dim}Status: Not found in registry${colors.reset}`,
      '',
    ].join('\n');
  }

  const vc = trustVerdictColor(answer.verdict);
  const tc = trustLevelColor(answer.trustLevel);

  const lines: string[] = [
    '',
    `  ${answer.name}`,
    `  Type:           ${answer.packageType || 'unknown'}`,
    `  Verdict:        ${vc}${answer.verdict.toUpperCase()}${colors.reset}`,
    `  Trust Level:    ${tc}${trustLevelLabel(answer.trustLevel)}${colors.reset} (${answer.trustLevel}/4)`,
    `  Trust Score:    ${Math.round(answer.trustScore * 100)}/100`,
    `  Scan Status:    ${answer.scanStatus || 'unknown'}`,
  ];

  if (answer.dependencies && answer.dependencies.totalDeps > 0) {
    const deps = answer.dependencies;
    lines.push('');
    lines.push('  Dependencies');
    lines.push(`  Total:          ${deps.totalDeps}`);
    lines.push(`  Vulnerable:     ${deps.vulnerableDeps > 0 ? colors.red + deps.vulnerableDeps + colors.reset : colors.green + '0' + colors.reset}`);
    lines.push(`  Min Trust:      ${deps.minTrustLevel}/4`);
  }

  lines.push('');
  return lines.join('\n');
}

function formatTrustBatch(
  response: { results: TrustAnswer[]; meta: { total: number; found: number; notFound: number } },
  minTrust: number
): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`  Trust Audit: ${response.meta.total} packages queried, ${response.meta.found} found, ${response.meta.notFound} not found`);
  lines.push('');

  const nameW = 40, typeW = 14, verdictW = 10, levelW = 12, scoreW = 8, scanW = 10;

  lines.push(
    '  ' +
    'PACKAGE'.padEnd(nameW) +
    'TYPE'.padEnd(typeW) +
    'VERDICT'.padEnd(verdictW) +
    'TRUST'.padEnd(levelW) +
    'SCORE'.padEnd(scoreW) +
    'SCAN'.padEnd(scanW)
  );
  lines.push('  ' + '-'.repeat(nameW + typeW + verdictW + levelW + scoreW + scanW));

  for (const result of response.results) {
    const vc = trustVerdictColor(result.verdict);
    const tc = trustLevelColor(result.trustLevel);

    const name = result.name.length > nameW - 2
      ? result.name.substring(0, nameW - 5) + '...'
      : result.name;

    lines.push(
      '  ' +
      name.padEnd(nameW) +
      (result.packageType || '-').padEnd(typeW) +
      vc + result.verdict.toUpperCase().padEnd(verdictW) + colors.reset +
      tc + trustLevelLabel(result.trustLevel).padEnd(levelW) + colors.reset +
      (result.found ? `${Math.round(result.trustScore * 100)}/100` : '-').padEnd(scoreW) +
      (result.scanStatus || '-').padEnd(scanW)
    );
  }

  const belowThreshold = response.results.filter((r) => r.found && r.trustLevel < minTrust);
  const notFound = response.results.filter((r) => !r.found);

  lines.push('');

  if (belowThreshold.length > 0) {
    lines.push(`  ${colors.yellow}[!] ${belowThreshold.length} package(s) below minimum trust level ${minTrust}:${colors.reset}`);
    for (const pkg of belowThreshold) {
      lines.push(`  ${colors.yellow}    - ${pkg.name} (trust level ${pkg.trustLevel}, verdict: ${pkg.verdict})${colors.reset}`);
    }
  }

  if (notFound.length > 0) {
    lines.push(`  ${colors.dim}[?] ${notFound.length} package(s) not found in registry:${colors.reset}`);
    for (const pkg of notFound) {
      lines.push(`  ${colors.dim}    - ${pkg.name}${colors.reset}`);
    }
  }

  if (belowThreshold.length === 0 && notFound.length === 0) {
    lines.push(`  ${colors.green}All ${response.meta.found} packages meet minimum trust level ${minTrust}.${colors.reset}`);
  }

  lines.push('');
  return lines.join('\n');
}

async function parseDepsFile(filePath: string): Promise<Array<{ name: string }>> {
  const fs = require('fs');
  const path = require('path');
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT') {
      throw new Error(`File not found: ${filePath}`);
    }
    throw err;
  }
  const fileName = path.basename(filePath);

  if (fileName === 'package.json') {
    const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    const packages: Array<{ name: string }> = [];
    const seen = new Set<string>();
    for (const deps of [pkg.dependencies, pkg.devDependencies]) {
      if (!deps) continue;
      for (const name of Object.keys(deps)) {
        if (!seen.has(name)) {
          seen.add(name);
          packages.push({ name });
        }
      }
    }
    return packages;
  }

  if (fileName === 'requirements.txt') {
    const packages: Array<{ name: string }> = [];
    const seen = new Set<string>();
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const match = line.match(/^([a-zA-Z0-9_-]+(?:\[[a-zA-Z0-9_,-]+\])?)/);
      if (match) {
        const name = match[1].replace(/\[.*\]/, '');
        if (!seen.has(name)) {
          seen.add(name);
          packages.push({ name });
        }
      }
    }
    return packages;
  }

  throw new Error(`Unsupported dependency file: ${fileName}. Supported: package.json, requirements.txt`);
}

program
  .command('trust')
  .description(`Check trust level for AI packages before installing

Query the OpenA2A Registry to verify trust scores, vulnerability status,
and dependency risk for MCP servers, A2A agents, and AI tools.

Modes:
  trust <package>           Single package lookup
  trust --audit <file>      Audit a dependency file (package.json, requirements.txt)
  trust --batch pkg1 pkg2   Batch lookup for multiple packages

Examples:
  $ ${CLI_PREFIX} trust @anthropic/claude-mcp
  $ ${CLI_PREFIX} trust server-filesystem          (resolves to @modelcontextprotocol/server-filesystem)
  $ ${CLI_PREFIX} trust mcp-server-fetch            (resolves to @modelcontextprotocol/server-fetch)
  $ ${CLI_PREFIX} trust my-mcp-server --type mcp_server
  $ ${CLI_PREFIX} trust --audit package.json
  $ ${CLI_PREFIX} trust --audit requirements.txt --min-trust 3
  $ ${CLI_PREFIX} trust --batch langchain openai anthropic`)
  .argument('[package]', 'Package name to look up')
  .option('-t, --type <type>', 'Package type (mcp_server, a2a_agent, ai_tool, etc.)')
  .option('--audit <file>', 'Audit a dependency file (package.json or requirements.txt)')
  .option('--batch <names...>', 'Batch trust lookup for multiple packages')
  .option('--min-trust <level>', 'Minimum trust level threshold (0-4)', '3')
  .option('--registry-url <url>', 'Registry base URL', REGISTRY_DEFAULT_URL)
  .option('--json', 'Output as JSON')
  .action(async (
    packageName: string | undefined,
    opts: {
      type?: string;
      audit?: string;
      batch?: string[];
      minTrust: string;
      registryUrl: string;
      json?: boolean;
    }
  ) => {
    const registryUrl = opts.registryUrl.replace(/\/+$/, '');
    const minTrust = parseInt(opts.minTrust, 10);
    if (isNaN(minTrust) || minTrust < 0 || minTrust > 4) {
      process.stderr.write('Error: --min-trust must be a number between 0 and 4\n');
      process.exit(1);
    }

    try {
      // Mode: audit a dependency file
      if (opts.audit) {
        const rawPackages = await parseDepsFile(opts.audit);
        const packages = rawPackages.map((pkg) => ({
          ...pkg,
          name: resolveAndLogMcpShorthand(pkg.name),
        }));
        if (packages.length === 0) {
          process.stdout.write('No dependencies found in the specified file.\n');
          return;
        }
        if (packages.length > 100) {
          process.stderr.write(`Error: Too many dependencies (${packages.length}). Maximum 100 per request.\n`);
          process.exit(1);
        }
        const response = await trustBatch(packages, registryUrl);
        if (opts.json) {
          writeJsonStdout(response);
        } else {
          process.stdout.write(formatTrustBatch(response, minTrust));
        }
        const belowThreshold = response.results.some((r) => r.found && r.trustLevel < minTrust);
        if (belowThreshold) process.exitCode = 1;
        return;
      }

      // Mode: batch lookup
      if (opts.batch && opts.batch.length > 0) {
        if (opts.batch.length > 100) {
          process.stderr.write(`Error: Too many packages (${opts.batch.length}). Maximum 100 per request.\n`);
          process.exit(1);
        }
        const packages = opts.batch.map((name) => ({
          name: resolveAndLogMcpShorthand(name),
          ...(opts.type ? { type: opts.type } : {}),
        }));
        const response = await trustBatch(packages, registryUrl);
        if (opts.json) {
          writeJsonStdout(response);
        } else {
          process.stdout.write(formatTrustBatch(response, minTrust));
        }
        const belowThreshold = response.results.some((r) => r.found && r.trustLevel < minTrust);
        if (belowThreshold) process.exitCode = 1;
        return;
      }

      // Mode: single package lookup
      if (!packageName) {
        process.stderr.write(`Error: Provide a package name or use --audit/--batch.\n`);
        process.stderr.write(`Usage: ${CLI_PREFIX} trust <package>\n`);
        process.exit(1);
      }

      packageName = resolveAndLogMcpShorthand(packageName);
      const result = await trustCheck(packageName, registryUrl, opts.type);
      if (opts.json) {
        writeJsonStdout(result);
      } else {
        process.stdout.write(formatTrustCheck(result));
      }
      if (result.found && (result.verdict === 'blocked' || result.verdict === 'warning')) {
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

program.parse();
