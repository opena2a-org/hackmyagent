/**
 * HMA-17 — a name-gated secret longer than 40 characters is invisible.
 *
 * The name-gated AWS-secret shape in
 * `src/nanomind-core/compiler/semantic-compiler.ts` pinned its value body to
 * exactly `{40}` and then forbade a further same-alphabet character with a
 * trailing lookahead. `{40}` consumes forty characters and the lookahead
 * rejects the forty-first, so a 41+ character secret assigned to
 * `AWS_SECRET_ACCESS_KEY` matched nothing. Measured on origin/main a598f61
 * (2026-09-01) with the built CLI: width 40 -> AST-CRED-003; widths 41, 50,
 * 64, 128 -> no credential finding.
 *
 * The CLI is driven through `src/cli.ts` with the repo's own `tsx`, not the
 * compiled binary, for the same reason `deterministic-floor-cli.test.ts`
 * documents: a spawn suite gated on the built entry can silently skip, and a
 * criterion whose evidence can silently skip is not evidence.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as semanticCompiler from '../../src/nanomind-core/compiler/semantic-compiler';

const REPO_ROOT = path.join(__dirname, '..', '..');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
const CLI_SRC = path.join(REPO_ROOT, 'src', 'cli.ts');

/**
 * Deterministic values over the shape's own alphabet `[A-Za-z0-9/+]`,
 * generated once by an LCG and frozen here as literals so the fixture bytes
 * are reviewable. Each shares the 40-char prefix (widths are prefixes of one
 * another), has 31+ distinct characters (clears the <=6 low-entropy sentinel
 * filter), and contains none of the placeholder markers
 * (FAKE/EXAMPLE/PLACEHOLDER/...) that would suppress the hit.
 */
const VALUE_BY_WIDTH: Record<number, string> = {
  40: 'gxg5HAuq1wTHXV6j47e9uPLYosPaq4SB1mZRHNET',
  41: 'gxg5HAuq1wTHXV6j47e9uPLYosPaq4SB1mZRHNETo',
  50: 'gxg5HAuq1wTHXV6j47e9uPLYosPaq4SB1mZRHNETobefRzLwbv',
  64: 'gxg5HAuq1wTHXV6j47e9uPLYosPaq4SB1mZRHNETobefRzLwbvdKmfvfUohc1Y2G',
  128: 'gxg5HAuq1wTHXV6j47e9uPLYosPaq4SB1mZRHNETobefRzLwbvdKmfvfUohc1Y2GAMa/usvmBwcQavaouGK01MFUSaifP7ZSaDWJwfRANWSx89utg0fg1qRDvYTivK2+',
};
const WIDTHS = [40, 41, 50, 64, 128] as const;

/**
 * The paired negative for the widening: a natural-language sentence of 66
 * characters on the name-gated line. Removing a fixed upper bound from a
 * credential shape is exactly the change that starts matching English, so
 * this must stay at zero credential findings.
 */
const PROSE_SENTENCE =
  'the deployment guide explains how operators rotate this value safely';

interface ReportFinding {
  checkId: string;
  severity: string;
  passed?: boolean;
}

function runCli(target: string): { failedCred: ReportFinding[]; stdout: string } {
  const run = spawnSync(TSX, [CLI_SRC, 'secure', target, '--no-registry', '--json'], {
    encoding: 'utf-8',
    timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1' },
  });
  const stdout = run.stdout ?? '';
  const start = stdout.indexOf('{');
  const parsed = start >= 0 ? JSON.parse(stdout.slice(start)) : {};
  const all: ReportFinding[] = parsed.allFindings ?? parsed.findings ?? [];
  return {
    failedCred: all.filter(f => f.passed === false && /^AST-CRED-/.test(f.checkId)),
    stdout,
  };
}

let root: string;
const credFindingsByWidth = new Map<number, ReportFinding[]>();
let proseFailedCred: ReportFinding[] = [];

beforeAll(() => {
  root = mkdtempSync(path.join(tmpdir(), 'hma17-'));
  for (const width of WIDTHS) {
    const dir = path.join(root, `w${width}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, 'config.py'),
      `AWS_SECRET_ACCESS_KEY = "${VALUE_BY_WIDTH[width]}"\n`,
    );
    credFindingsByWidth.set(width, runCli(dir).failedCred);
  }
  const proseDir = path.join(root, 'prose');
  mkdirSync(proseDir, { recursive: true });
  writeFileSync(
    path.join(proseDir, 'config.py'),
    `AWS_SECRET_ACCESS_KEY = "${PROSE_SENTENCE}"\n`,
  );
  proseFailedCred = runCli(proseDir).failedCred;
}, 1_200_000);

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describe('HMA-17 name-gated credential width', () => {
  it('HMA-17.AC1 a 50-character name-gated value in a .py fixture produces a failed AST-CRED-* finding', () => {
    const failed = credFindingsByWidth.get(50) ?? [];
    expect(
      failed.length,
      'a 50-character secret assigned to AWS_SECRET_ACCESS_KEY must produce at least one '
        + 'failed AST-CRED-* finding; on origin/main a598f61 the {40}-pinned body plus the '
        + 'same-alphabet lookahead makes any 41+ character secret invisible',
    ).toBeGreaterThanOrEqual(1);
  }, 30_000);

  for (const width of WIDTHS) {
    it(`HMA-17.AC2 width ${width}: the name-gated fixture produces a failed AST-CRED-* finding`, () => {
      const failed = credFindingsByWidth.get(width) ?? [];
      expect(
        failed.length,
        `body length ${width} assigned to AWS_SECRET_ACCESS_KEY must be detected; the shape `
          + 'declares a canonical MINIMUM of 40, not an exact width',
      ).toBeGreaterThanOrEqual(1);
    }, 30_000);
  }

  it('HMA-17.AC4 a natural-language sentence of 50+ characters on the name-gated line produces zero failed AST-CRED-* findings', () => {
    expect(PROSE_SENTENCE.length).toBeGreaterThanOrEqual(50);
    expect(
      proseFailedCred.map(f => f.checkId),
      'prose assigned to AWS_SECRET_ACCESS_KEY must not be reported as a credential: the '
        + 'value alphabet [A-Za-z0-9/+] excludes spaces, and the widening must not relax it',
    ).toEqual([]);
  }, 30_000);

  it('HMA-17.AC5 no name-gated pattern pairs a fixed-width {N} body with a trailing lookahead over the same alphabet', () => {
    // Namespace import, not a named one: on origin/main this export does not
    // exist, and a named import would fail the whole file at module init
    // rather than reporting which arm is red.
    const accessor = (
      semanticCompiler as unknown as {
        nameGatedCredentialPatternsForTest?: () => Array<{ label: string; regex: RegExp }>;
      }
    ).nameGatedCredentialPatternsForTest;
    expect(
      typeof accessor,
      'the compiler must export nameGatedCredentialPatternsForTest so this class is '
        + 'asserted structurally rather than swept by hand',
    ).toBe('function');

    const patterns = accessor!();
    expect(patterns.length).toBeGreaterThanOrEqual(1);

    // A character class, a fixed-width quantifier closing the capture, then a
    // negative lookahead over the SAME class text. `{40}` consumes exactly N
    // characters and the lookahead rejects the N+1th, so any entry with this
    // shape detects exactly one width and nothing longer — the defect this
    // suite exists for. Measured at origin/main a598f61 the population was
    // exactly one (semantic-compiler.ts:1657); this refuses a re-introduction.
    const fixedWidthSameAlphabetLookahead = /(\[[^\]]+\])\{\d+\}\)?\(\?!\1/;
    const offenders = patterns
      .filter(p => fixedWidthSameAlphabetLookahead.test(p.regex.source))
      .map(p => `${p.label}: /${p.regex.source}/`);
    expect(
      offenders,
      'these name-gated shapes pin an exact width and then forbid a same-alphabet '
        + 'continuation, so any longer secret is invisible; use a lower bound {N,} instead',
    ).toEqual([]);
  }, 30_000);
});
