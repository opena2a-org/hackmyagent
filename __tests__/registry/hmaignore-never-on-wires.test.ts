/**
 * HMA-21.AC4 — the per-rule `.hmaignore` disclosure never rides a wire
 * (CA (3)). Same shape as `settled-outcome-wires.test.ts`: build a
 * `ScanResult` that CARRIES the `hmaignore` key, run it through every
 * outbound builder, and assert `'hmaignore' in payload === false` on each.
 *
 * The disclosure necessarily carries paths and free-text reasons; the
 * settled record carries no path by construction, and `.hmaignore` reasons
 * are repository-local policy text with no Registry reader.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { settledOutcome, SETTLED_OUTCOME_KEYS, type SettledOutcome } from '../../src/hardening/settled-outcome';
import { buildPublishPayload } from '../../src/registry/publish';
import { buildScanReport, buildCommunityReport } from '../../src/registry/client';
import { buildScanEvent } from '../../src/telemetry/contribute';
import { emitFindings } from '../../src/hardening/finding-emit';
import { isScopeChannel, type ScopeChannel, type PresentationalChannel, type SuppressionChannel } from '../../src/hardening/security-check';
import type { ScanResult } from '../../src/hardening/security-check';

// ── Compile-level guard: `hmaignore` is not a key of `SettledOutcome`. ──────
// Under `tsc` this line stops compiling the day someone adds the field "for
// completeness"; the runtime assertions below catch the same drift in CI.
type HmaignoreNeverAKeyOfSettledOutcome = 'hmaignore' extends keyof SettledOutcome ? never : true;
const _wireGuard: HmaignoreNeverAKeyOfSettledOutcome = true;
void _wireGuard;

function draft(checkId: string, severity: string, passed: boolean) {
  return {
    checkId,
    name: checkId,
    description: `fixture ${checkId}`,
    category: 'config',
    severity: severity as any,
    passed,
    message: 'x',
    fixable: false,
  };
}

const hmaignore: NonNullable<ScanResult['hmaignore']> = {
  file: '.hmaignore',
  rules: [
    { line: 1, rule: 'danger.py:NEMO-009 # fp', channel: 'hmaignore-path-check', path: 'danger.py', checkId: 'NEMO-009', reason: 'fp', matched: 1 },
  ],
  errors: [{ line: 2, rule: '*.py', error: 'globs are not supported in path rules' }],
};

function makeResult(): ScanResult {
  return {
    timestamp: new Date(),
    platform: 'test',
    projectType: 'library',
    findings: emitFindings([draft('ENV-001', 'high', false)]),
    score: 61,
    maxScore: 100,
    outOfScope: [{ checkId: 'NEMO-009', name: 'x', category: 'nemo', severity: 'critical', count: 1, suppressedBy: 'hmaignore-path-check' }],
    hmaignore,
    coverage: {
      filesExamined: 3,
      executions: [{ method: 'a', prefixes: [], completed: true, filesRead: 3, pathsInspected: 3 }],
      truncations: [],
      unreadableInputs: { count: 0, codes: {}, directories: 0 },
    },
  } as unknown as ScanResult;
}

describe('HMA-21.AC4 — hmaignore never on a wire', () => {
  const r = makeResult();
  const settled = settledOutcome(r, 1);

  it('HMA-21.AC4 settled-outcome.ts: the record excludes it, and SETTLED_OUTCOME_KEYS cannot pick it up', () => {
    expect('hmaignore' in settled).toBe(false);
    expect(SETTLED_OUTCOME_KEYS as readonly string[]).not.toContain('hmaignore');
    // the scope rows themselves still ride (additive value in an open field)
    expect(settled.outOfScope?.[0]?.suppressedBy).toBe('hmaignore-path-check');
  });

  it('HMA-21.AC4 publish.ts: buildPublishPayload carries no hmaignore', () => {
    const p = buildPublishPayload(
      { packageName: 'fx', directory: '/tmp/fx', hardeningFindings: r.findings } as any,
      '0.33.0',
      settled,
    );
    expect('hmaignore' in p).toBe(false);
  });

  it('HMA-21.AC4 registry/client.ts: buildScanReport and buildCommunityReport carry no hmaignore, in rawReport included', () => {
    const scan = buildScanReport('v-1', r.findings as any, settled);
    expect('hmaignore' in scan).toBe(false);
    expect('hmaignore' in (scan.rawReport as object)).toBe(false);
    expect('hmaignore' in ((scan.rawReport as any).settledOutcome ?? {})).toBe(false);
    const community = buildCommunityReport('fx', r.findings as any, {}, settled);
    expect('hmaignore' in community).toBe(false);
    expect('hmaignore' in (community.rawReport as object)).toBe(false);
  });

  it('HMA-21.AC4 telemetry/contribute.ts: buildScanEvent carries no hmaignore', () => {
    const event = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900, settled, 1);
    expect('hmaignore' in event).toBe(false);
    expect('hmaignore' in (event.scanSummary as object)).toBe(false);
  });

  it('HMA-21.AC4 cli.ts publish arm: the ci rawReport is built from named keys and never references hmaignore', () => {
    const cliSrc = fs.readFileSync(path.resolve(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
    const arm = cliSrc.match(/submitCIScanResult\(\{[\s\S]*?\}\);/);
    expect(arm, 'the ci publish arm moved — re-point this guard').not.toBeNull();
    expect(arm![0]).not.toContain('hmaignore');
    // and no wire builder spreads ScanResult wholesale
    expect(arm![0]).not.toMatch(/\.\.\.result\b/);
  });

  it('HMA-21.AC4 SuppressionChannel is split into PresentationalChannel | ScopeChannel with isScopeChannel exported', () => {
    // type-level: assignability in both directions is what the split means
    const scope: ScopeChannel = 'hmaignore-path-check';
    const presentational: PresentationalChannel = 'hmaignore-check';
    const union: SuppressionChannel[] = [scope, presentational, 'hmaignore-path', 'ignore-flag'];
    expect(union).toHaveLength(4);
    // value-level: the one spelling of the partition
    expect(isScopeChannel('hmaignore-path')).toBe(true);
    expect(isScopeChannel('hmaignore-path-check')).toBe(true);
    expect(isScopeChannel('hmaignore-check')).toBe(false);
    expect(isScopeChannel('ignore-flag')).toBe(false);
    expect(isScopeChannel('some-future-channel')).toBe(false);
  });
});
