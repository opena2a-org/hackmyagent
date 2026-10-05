#!/usr/bin/env tsx
/**
 * release-smoke-corpus.ts — opena2a-corpus consumer harness for HMA.
 *
 * Walks ~/.opena2a/corpus/, runs `hackmyagent secure --json` against every
 * fixture whose surface is in our consumer block of corpus-manifest.yaml,
 * and asserts:
 *
 *   1. score is within manifest.expected.hma.score.{min,max}
 *   2. every entry in manifest.expected.hma.findings appears in CLI output
 *      (matched by checkId)
 *   3. no entry in manifest.expected.hma.mustNotFind appears
 *   4. for soul-surface fixtures, `hackmyagent scan-soul --json` agrees with
 *      the fixture's intent in direction (see SOUL_SURFACE below)
 *
 * Corpus drift surfaces in this harness, before publish.
 * OPENA2A_CORPUS_DETERMINISTIC=1 is set so the output is stable across runs.
 * This harness lives in this repository; ai-trust and opena2a-cli ship their
 * own.
 *
 * Exit code 0 = green, 1 = drift, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import yaml from 'js-yaml';
import { evidenceCitationProblem } from '../src/types/redacted-evidence';

interface ExpectedFinding {
  checkId: string;
  severity?: string;
  rationale?: string;
}

interface CliExpectation {
  score?: { min: number; max: number };
  verdict?: string;
  findings?: ExpectedFinding[];
  mustNotFind?: ExpectedFinding[];
}

interface FixtureManifest {
  fixture: string;
  surface: string;
  intent: string;
  expected?: { hma?: CliExpectation };
}

interface CorpusManifest {
  corpusName: string;
  corpusVersion: string;
  consumers: { name: string; surfaces: string[] }[];
  surfaceIndex: Record<string, Record<string, string[]>>;
}

const CORPUS_ROOT =
  process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus');
const HMA_CLI = resolve(__dirname, '..', 'dist', 'cli.js');
const CONSUMER_NAME = 'hackmyagent';

function fail(msg: string, code = 2): never {
  process.stderr.write(`release-smoke-corpus: ${msg}\n`);
  process.exit(code);
}

function loadCorpusManifest(): CorpusManifest {
  const path = join(CORPUS_ROOT, 'corpus-manifest.yaml');
  if (!existsSync(path)) {
    fail(
      `corpus not found at ${CORPUS_ROOT}\n` +
        `clone it: git clone https://github.com/opena2a-org/opena2a-corpus.git ${CORPUS_ROOT}\n` +
        `or set OPENA2A_CORPUS_PATH to a local checkout.`,
    );
  }
  return yaml.load(readFileSync(path, 'utf8')) as CorpusManifest;
}

function loadFixtureManifest(path: string): FixtureManifest {
  return yaml.load(readFileSync(path, 'utf8')) as FixtureManifest;
}

function consumerSurfaces(corpus: CorpusManifest): string[] {
  const me = corpus.consumers.find((c) => c.name === CONSUMER_NAME);
  if (!me) fail(`consumer '${CONSUMER_NAME}' not in corpus-manifest.yaml`);
  return me.surfaces;
}

function fixtureScanTarget(fixtureDir: string): string {
  // For repo/* fixtures HMA scans the directory; for mcp/skill/soul it also
  // scans the directory (HMA picks up artifact files inside).
  return fixtureDir;
}

interface RawFinding {
  checkId: string;
  severity: string;
  passed?: boolean;
  file?: string;
  line?: number;
  evidence?: {
    kind?: string;
    lines?: Array<{ n: number; content: string }>;
    observed?: { lines?: Array<{ n: number; content: string }> };
    positive?: { lines?: Array<{ n: number; content: string }> };
  };
}

interface HmaResult {
  score: number;
  findings: string[];
  severities: Record<string, number>;
  rawFindings: RawFinding[];
}

function runHma(target: string): HmaResult {
  const env = { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' };
  const r = spawnSync(process.execPath, [HMA_CLI, 'secure', target, '--json'], {
    encoding: 'utf8',
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.status !== 0 && !r.stdout) {
    return {
      score: -1,
      findings: [`__hma_exit_${r.status}__`],
      severities: {},
      rawFindings: [],
    };
  }
  const data = JSON.parse(r.stdout);
  const fails = ((data.allFindings ?? data.findings ?? []) as RawFinding[]).filter(
    (f) => f.passed === false,
  );
  const findings = [...new Set(fails.map((f) => f.checkId))].sort();
  const severities = fails.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  return {
    score: typeof data.score === 'number' ? data.score : -1,
    findings,
    severities,
    rawFindings: fails,
  };
}

/**
 * Issue #141 — every finding HMA emits with file+line must produce a
 * working Verify command. The Verify generator pulls `sed -n '<line>p'
 * <file>` so the test here is straightforward: read the cited line and
 * assert it's non-empty. When the finding also carries
 * `evidence.lines[0].content`, assert the line at that position matches
 * the cited content (substring) — that's what catches "wrong line"
 * regressions where the detector populated `line` with something the
 * file doesn't actually contain at that location.
 *
 * Findings without `file+line` are not checked — `generateVerifyCommand`
 * returns undefined for them (no Verify line is shown to the user) so
 * there's nothing to validate.
 */
function firstEvidenceLine(f: RawFinding): { n: number; content: string } | undefined {
  const e = f.evidence;
  if (!e) return undefined;
  if (e.kind === 'positive') return e.lines?.[0];
  if (e.kind === 'absence') return e.observed?.lines?.[0];
  if (e.kind === 'mixed') return e.positive?.lines?.[0];
  return undefined;
}

function verifyAssertions(fixtureDir: string, findings: RawFinding[]): string[] {
  const reasons: string[] = [];
  for (const f of findings) {
    if (!f.file || !f.line || f.line < 1) continue;
    const filePath = resolve(fixtureDir, f.file);
    let lineContent: string;
    try {
      const content = readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      lineContent = lines[f.line - 1] ?? '';
    } catch (err) {
      reasons.push(
        `verify: ${f.checkId} cites ${f.file}:${f.line} — file unreadable (${(err as Error).message})`,
      );
      continue;
    }
    if (lineContent.trim() === '') {
      reasons.push(
        `verify: ${f.checkId} cites ${f.file}:${f.line} — line is empty (sed -n would return nothing)`,
      );
      continue;
    }
    const evLine = firstEvidenceLine(f);
    if (evLine && evLine.content) {
      const ev = evLine.content.trim();
      // Detectors redact secret values in evidence text so credentials
      // don't leak into logs / diffs, so compare on the fragments either
      // side of each marker rather than on the full string. The
      // line-existence check above already gates that the cited position
      // is real; this only relaxes the substring match, and every
      // non-empty fragment must still be on the line.
      //
      // The marker vocabulary lives in src/types/redacted-evidence.ts and
      // is a SHAPE, not a literal. It used to be the single literal
      // `[REDACTED]`, which recognised one of the four marker families the
      // tree emits — `'[REDACTED_GITHUB_TOKEN]'.includes('[REDACTED]')` is
      // false — so any typed or lowercase marker failed this gate while
      // citing its line correctly.
      const problem = evidenceCitationProblem(ev, lineContent);
      if (problem?.kind === 'pure-marker') {
        reasons.push(
          `verify: ${f.checkId} cites ${f.file}:${f.line} — evidence is a redaction marker with no surrounding content; emit site must include literal context around the redaction`,
        );
      } else if (problem?.kind === 'missing-segment') {
        reasons.push(
          `verify: ${f.checkId} cites ${f.file}:${f.line} — line content doesn't include redacted-evidence segment (line=${JSON.stringify(lineContent.slice(0, 60))}, missing=${JSON.stringify(problem.missing.slice(0, 60))})`,
        );
      } else if (problem?.kind === 'evidence-absent') {
        reasons.push(
          `verify: ${f.checkId} cites ${f.file}:${f.line} — line content doesn't include evidence (line=${JSON.stringify(lineContent.slice(0, 60))}, evidence=${JSON.stringify(ev.slice(0, 60))})`,
        );
      }
    }
  }
  return reasons;
}

function renderGolden(r: HmaResult): string {
  const sevSorted = Object.fromEntries(Object.entries(r.severities).sort());
  return [
    `score=${r.score}`,
    `severities=${JSON.stringify(sevSorted)}`,
    `checkIds=${r.findings.join(',')}`,
    '',
  ].join('\n');
}

const UPDATE_GOLDEN = process.env.OPENA2A_CORPUS_UPDATE_GOLDEN === '1';
const GOLDEN_ROOT = resolve(__dirname, '..', 'golden', 'hma');

function diffFixture(
  fixtureRel: string,
  fixtureDir: string,
  manifest: FixtureManifest,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const expected = manifest.expected?.hma;
  if (!expected) {
    return {
      ok: true,
      reasons: ['skipped: manifest declares no hma expectation'],
    };
  }
  const result = runHma(fixtureScanTarget(fixtureDir));
  const { score, findings } = result;
  if (score === -1) {
    reasons.push(`hma exited non-zero (findings=${findings.join(',')})`);
    return { ok: false, reasons };
  }
  if (expected.score) {
    if (score < expected.score.min || score > expected.score.max) {
      reasons.push(
        `score ${score} outside [${expected.score.min}, ${expected.score.max}]`,
      );
    }
  }
  for (const f of expected.findings ?? []) {
    if (!findings.includes(f.checkId)) {
      reasons.push(`missing expected finding ${f.checkId}`);
    }
  }
  for (const f of expected.mustNotFind ?? []) {
    if (findings.includes(f.checkId)) {
      reasons.push(`unexpected finding ${f.checkId} (mustNotFind)`);
    }
  }
  // Issue #141: every finding with file+line must produce a Verify command
  // that resolves to a non-empty line, with optional evidence-content match.
  reasons.push(...verifyAssertions(fixtureDir, result.rawFindings));
  // Golden snapshot diff (lock the full output shape, not just expected
  // findings — catches drift in the noise-floor checks too).
  const goldenPath = join(GOLDEN_ROOT, fixtureRel, 'output.txt');
  const rendered = renderGolden(result);
  if (UPDATE_GOLDEN) {
    require('node:fs').mkdirSync(dirname(goldenPath), { recursive: true });
    require('node:fs').writeFileSync(goldenPath, rendered);
  } else if (existsSync(goldenPath)) {
    const golden = readFileSync(goldenPath, 'utf8');
    if (golden !== rendered) {
      reasons.push(
        `golden mismatch — re-run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to update`,
      );
    }
  } else {
    reasons.push(
      `golden missing at ${goldenPath} — run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to bake`,
    );
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * #503 — a soul fixture is also scored by the soul analyzer.
 *
 * `secure` and `scan-soul` read the same SOUL.md and can disagree in
 * direction: soul/benign/hardened-soul sits inside its `secure` band while
 * `scan-soul` exits 1 on it (conformance none). When this harness drove
 * `secure` alone, that disagreement never reached its output.
 *
 * What fails the run is drift in the soul analyzer's direction:
 *   - scan-soul gives no verdict (exit other than 0/1, or no JSON score)
 *   - a malicious fixture passes scan-soul (exit 0)
 *   - a benign fixture earns governance violations
 *   - a benign fixture does not score strictly above every malicious one
 *
 * A benign fixture that scan-soul fails is printed as a `note:` and counted
 * in the summary, not failed. That is the current state of hardened-soul,
 * pinned in __tests__/soul/soul-corpus-direction.test.ts: its role-play
 * refusal is written as prose the keyword matcher does not detect (#266).
 * The line is there so the release reads it on every run; it is not a
 * verdict this harness settles on its own.
 */
const SOUL_SURFACE = 'soul';

interface ScanSoulResult {
  exitCode: number;
  score: number;
  conformance: string;
  criticalMissing: string[];
  violations: number;
}

interface SoulRow {
  fixtureRel: string;
  intent: string;
  result: ScanSoulResult;
}

function runScanSoul(target: string): ScanSoulResult | { error: string } {
  const env = { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' };
  const r = spawnSync(process.execPath, [HMA_CLI, 'scan-soul', target, '--json'], {
    encoding: 'utf8',
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  const stdout = r.stdout ?? '';
  const start = stdout.indexOf('{');
  let data:
    | {
        score?: unknown;
        conformance?: unknown;
        criticalMissing?: unknown;
        violations?: unknown;
        gate?: { reason?: unknown };
      }
    | undefined;
  if (start >= 0) {
    try {
      data = JSON.parse(stdout.slice(start));
    } catch {
      data = undefined;
    }
  }
  const status = r.status;
  if (status !== 0 && status !== 1) {
    const why = typeof data?.gate?.reason === 'string' ? ` (${data.gate.reason})` : '';
    return { error: `scan-soul exited ${status ?? r.signal}${why}, so it gave no verdict` };
  }
  if (!data || typeof data.score !== 'number') {
    return { error: `scan-soul --json printed no score (exit ${status})` };
  }
  return {
    exitCode: status,
    score: data.score,
    conformance: String(data.conformance),
    criticalMissing: Array.isArray(data.criticalMissing) ? data.criticalMissing.map(String) : [],
    violations: Array.isArray(data.violations) ? data.violations.length : 0,
  };
}

function scoreSoulFixture(
  fixtureRel: string,
  intent: string,
  fixtureDir: string,
): { reasons: string[]; lines: string[]; noted: boolean; row?: SoulRow } {
  const result = runScanSoul(fixtureScanTarget(fixtureDir));
  if ('error' in result) {
    return { reasons: [result.error], lines: [], noted: false };
  }
  const reasons: string[] = [];
  const lines = [
    `scan-soul: score=${result.score} conformance=${result.conformance} ` +
      `exit=${result.exitCode} criticalMissing=${result.criticalMissing.join(',') || '-'} ` +
      `violations=${result.violations}`,
  ];
  if (intent === 'malicious' && result.exitCode === 0) {
    reasons.push(
      `scan-soul passes a malicious fixture (exit 0, conformance ${result.conformance})`,
    );
  }
  if (intent === 'benign' && result.violations > 0) {
    reasons.push(
      `scan-soul reports ${result.violations} governance violation(s) on a benign fixture`,
    );
  }
  const noted = intent === 'benign' && result.exitCode !== 0;
  if (noted) {
    const undetected = result.criticalMissing.length
      ? `; critical control not detected: ${result.criticalMissing.join(', ')}`
      : '';
    lines.push(
      `note: scan-soul fails this benign fixture (exit ${result.exitCode}, ` +
        `conformance ${result.conformance}${undetected}); printed, not counted`,
    );
  }
  return { reasons, lines, noted, row: { fixtureRel, intent, result } };
}

function scanSoulDegreeFailures(rows: SoulRow[]): string[] {
  const failures: string[] = [];
  for (const b of rows.filter((r) => r.intent === 'benign')) {
    for (const m of rows.filter((r) => r.intent === 'malicious')) {
      if (b.result.score <= m.result.score) {
        failures.push(
          `scan-soul degree: ${b.fixtureRel} (${b.result.score}) does not score above ` +
            `${m.fixtureRel} (${m.result.score})`,
        );
      }
    }
  }
  return failures;
}

function main(): void {
  if (!existsSync(HMA_CLI)) {
    fail(
      `dist/cli.js not built. run \`npm run build\` first.`,
    );
  }
  const corpus = loadCorpusManifest();
  const surfaces = consumerSurfaces(corpus);
  process.stdout.write(
    `release-smoke-corpus: ${corpus.corpusName} ${corpus.corpusVersion}\n` +
      `consumer: ${CONSUMER_NAME}, surfaces: ${surfaces.join(',')}\n` +
      `corpus path: ${CORPUS_ROOT}\n\n`,
  );

  let pass = 0;
  let fail_ = 0;
  let skip = 0;
  let soulNoted = 0;
  for (const surface of surfaces) {
    const surfaceDir = join(CORPUS_ROOT, surface);
    if (!existsSync(surfaceDir)) {
      process.stdout.write(`  skip ${surface}/* — surface directory not present (Phase 3?)\n`);
      skip++;
      continue;
    }
    const soulRows: SoulRow[] = [];
    for (const intent of ['benign', 'buggy', 'malicious']) {
      const intentDir = join(surfaceDir, intent);
      if (!existsSync(intentDir)) continue;
      for (const fixtureName of readdirSync(intentDir)) {
        const fixtureDir = join(intentDir, fixtureName);
        if (!statSync(fixtureDir).isDirectory()) continue;
        const manifestPath = join(fixtureDir, 'manifest.yaml');
        if (!existsSync(manifestPath)) continue;
        const manifest = loadFixtureManifest(manifestPath);
        const fixtureRel = `${surface}/${intent}/${fixtureName}`;
        const r = diffFixture(fixtureRel, fixtureDir, manifest);
        const soul =
          surface === SOUL_SURFACE
            ? scoreSoulFixture(fixtureRel, intent, fixtureDir)
            : undefined;
        if (soul?.row) soulRows.push(soul.row);
        if (soul?.noted) soulNoted++;
        const reasons = [...(r.ok ? [] : r.reasons), ...(soul?.reasons ?? [])];
        if (reasons.length === 0) {
          process.stdout.write(`  ok   ${fixtureRel}\n`);
          pass++;
        } else {
          process.stdout.write(`  FAIL ${fixtureRel}\n`);
          for (const reason of reasons) {
            process.stdout.write(`         ${reason}\n`);
          }
          fail_++;
        }
        for (const line of soul?.lines ?? []) {
          process.stdout.write(`         ${line}\n`);
        }
      }
    }
    for (const failure of scanSoulDegreeFailures(soulRows)) {
      process.stdout.write(`  FAIL ${failure}\n`);
      fail_++;
    }
  }
  process.stdout.write(`\n${pass} passed, ${fail_} failed, ${skip} skipped\n`);
  if (soulNoted > 0) {
    process.stdout.write(
      `${soulNoted} benign soul fixture(s) fail scan-soul (the note: lines above; printed, not counted)\n`,
    );
  }
  process.exit(fail_ === 0 ? 0 : 1);
}

main();
