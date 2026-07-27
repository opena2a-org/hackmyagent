// Regression gate for two scope bugs in the #259 verdict-band clamp.
//
// H-6 — the clamp fired on findings `--fix` had already resolved.
//   `isFailDirection` filtered only `passed`, while `calculateSecurityScore`
//   filters `!passed && !fixed`. Both are handed the same `filteredFindings`,
//   which deliberately retains fixed findings so a run can report what it
//   repaired. A `secure --fix` that fixed everything therefore scored a raw
//   100 and was clamped to 69 for findings that no longer existed:
//
//     Score: 69/100 | 0 issues found | 2 fixed
//
//   That is #259 inverted — a capped number beside a clean verdict. `secure`
//   escaped it because its NanoMind merge re-runs `applyScore()` with
//   `!passed && !fixed`; `mcp-server.ts`'s `hackmyagent_scan` did not.
//
// H-7 — the Registry publish path bypassed the clamp entirely.
//   `registry/publish.ts` built its own composite with a bare
//   `calculateSecurityScore`, so the Registry received 76 where the CLI
//   showed 69 — while the scanner's own #259 comment claims "`--json` and the
//   Registry carry the same figure the terminal shows". `score` is part of
//   the signed strong canonical, so the signature attested a number the tool
//   never displayed.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  GOOD_BAND_FLOOR,
  VERDICT_FAIL_CLAMP,
  clampScoreToVerdictBand,
  isFailDirection,
} from '../../src/ui/verdict-band';

const SRC = join(__dirname, '..', '..', 'src');

describe('H-6: a fixed finding is not fail-direction', () => {
  it('does not clamp when every high/critical was auto-fixed', () => {
    // The shape `secure --fix` produces: retained for reporting, excluded
    // from the score.
    const fixed = [
      { severity: 'high', passed: false, fixed: true },
      { severity: 'low', passed: false, fixed: true },
    ];
    expect(isFailDirection(fixed)).toBe(false);
    // rawScore 100 is what calculateSecurityScore returns for this set,
    // because it filters `!passed && !fixed`. The clamp must agree.
    expect(clampScoreToVerdictBand(100, fixed)).toEqual({ score: 100, clamped: false });
  });

  it('still clamps when an unfixed high remains alongside a fixed one', () => {
    // Non-vacuity for the case above: the clamp must not have been disabled
    // wholesale. One genuine outstanding high is still fail-direction.
    const mixed = [
      { severity: 'high', passed: false, fixed: true },
      { severity: 'high', passed: false },
    ];
    expect(isFailDirection(mixed)).toBe(true);
    expect(clampScoreToVerdictBand(88, mixed)).toEqual({
      score: VERDICT_FAIL_CLAMP,
      clamped: true,
    });
  });

  it('agrees with the scoring filter on every passed/fixed combination', () => {
    // `calculateSecurityScore` counts a finding iff `!passed && !fixed`.
    // The clamp's direction test must use the identical predicate, or the
    // number and the cap are computed off different evidence — which is the
    // whole defect class #259 exists to close.
    const counts = (f: { passed?: boolean; fixed?: boolean }) => !f.passed && !f.fixed;
    for (const passed of [true, false, undefined]) {
      for (const fixed of [true, false, undefined]) {
        const f = { severity: 'critical', passed, fixed };
        expect(isFailDirection([f]), `passed=${passed} fixed=${fixed}`).toBe(counts(f));
      }
    }
  });
});

describe('H-7: no published surface computes a composite without the clamp', () => {
  it('the registry publish path applies the clamp', () => {
    const src = readFileSync(join(SRC, 'registry', 'publish.ts'), 'utf8');
    expect(src).toMatch(/clampScoreToVerdictBand/);
  });

  it('publishes rawScore and scoreClamped so a clamp is detectable downstream', () => {
    // Without both fields a Registry dashboard plotting history cannot tell
    // "the scoring rule changed across HMA versions" from "this agent got
    // worse" — the same argument #206 made for subReports.soul.
    const src = readFileSync(join(SRC, 'registry', 'publish.ts'), 'utf8');
    expect(src).toMatch(/rawScore, scoreClamped/);
  });

  it('leaves no bare calculateSecurityScore on a scoring surface', () => {
    // The sweep that catches the next one. #259 was closed three times —
    // once in the scanner, once for the `check` quick scan, once here —
    // because each new composite site was found by hand. This asserts the
    // property directly: every call that produces a rendered or published
    // composite must be clamped within the same block.
    // Wide enough to span an explanatory comment between the call and its
    // clamp (the quick-scan site has 16 lines of rationale in between),
    // narrow enough to still mean "the same block".
    const LOOKAHEAD = 25;
    const offenders: string[] = [];
    for (const rel of [['registry', 'publish.ts'], ['cli.ts']]) {
      const lines = readFileSync(join(SRC, ...rel), 'utf8').split('\n');
      lines.forEach((line, i) => {
        const trimmed = line.trimStart();
        if (!line.includes('calculateSecurityScore(')) return;
        if (trimmed.startsWith('*') || trimmed.startsWith('//') || line.includes('import')) return;
        const window = lines.slice(i, i + LOOKAHEAD).join('\n');
        if (window.includes('clampScoreToVerdictBand')) return;
        offenders.push(`${rel.join('/')}:${i + 1}: ${trimmed}`);
      });
    }
    expect(offenders, `unclamped composite site(s):\n${offenders.join('\n')}`).toEqual([]);
  });
});

describe('the #259 contract still holds', () => {
  it('an outstanding high in the good band is still floored', () => {
    // The original bug. If this ever stops failing, the clamp is gone.
    expect(clampScoreToVerdictBand(76, [{ severity: 'high', passed: false }])).toEqual({
      score: VERDICT_FAIL_CLAMP,
      clamped: true,
    });
    expect(VERDICT_FAIL_CLAMP).toBeLessThan(GOOD_BAND_FLOOR);
  });
});
