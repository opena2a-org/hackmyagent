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
  countsAgainstScore,
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

  it('a fix the verification pass could not confirm still counts (A2)', () => {
    // Checks set `fixed: autoFix && !passed` BEFORE knowing the write landed.
    // PERM-001 swallows a failed `fs.chmod` (immutable flag, EPERM, read-only
    // mount) and still reports `fixed: true` on a file that is still
    // world-readable; the verification pass then sets `fixVerified: false`
    // and appends "[FIX NOT VERIFIED - issue may persist]".
    //
    // Excluding on `fixed` alone scored that 100/100 — a clean number for an
    // unfixed high — which is how `mcp-server.ts` rendered
    // "Score: 100/100 | 0 issues found | 1 fixed" for a still-exposed file.
    const unverified = [{ severity: 'high', passed: false, fixed: true, fixVerified: false }];
    expect(countsAgainstScore(unverified[0])).toBe(true);
    expect(isFailDirection(unverified)).toBe(true);
    expect(clampScoreToVerdictBand(100, unverified)).toEqual({
      score: VERDICT_FAIL_CLAMP,
      clamped: true,
    });

    // A confirmed fix is genuinely resolved and must not be clamped.
    const verified = [{ severity: 'high', passed: false, fixed: true, fixVerified: true }];
    expect(isFailDirection(verified)).toBe(false);
    expect(clampScoreToVerdictBand(100, verified)).toEqual({ score: 100, clamped: false });
  });

  it('agrees with the scoring filter on every passed/fixed/fixVerified combination', () => {
    // The single predicate `countsAgainstScore` now backs BOTH
    // `calculateSecurityScore` and `isFailDirection`. If they ever diverge
    // again the number and the cap are computed off different evidence —
    // the whole defect class #259 exists to close.
    for (const passed of [true, false, undefined]) {
      for (const fixed of [true, false, undefined]) {
        for (const fixVerified of [true, false, undefined]) {
          const f = { severity: 'critical', passed, fixed, fixVerified };
          const label = `passed=${passed} fixed=${fixed} fixVerified=${fixVerified}`;
          expect(isFailDirection([f]), label).toBe(countsAgainstScore(f));
        }
      }
    }
  });

  it('countsAgainstScore encodes exactly the intended rule', () => {
    // Spelled out rather than mirrored from the implementation, so this
    // fails if the rule itself is changed.
    expect(countsAgainstScore({ passed: true })).toBe(false);
    expect(countsAgainstScore({ passed: false })).toBe(true);
    expect(countsAgainstScore({ passed: false, fixed: true })).toBe(false);
    expect(countsAgainstScore({ passed: false, fixed: true, fixVerified: true })).toBe(false);
    expect(countsAgainstScore({ passed: false, fixed: true, fixVerified: false })).toBe(true);
  });
});

describe('H-7: no published surface computes a composite without the clamp', () => {
  // Behavioral, not a source grep. An earlier draft of these two asserted
  // `/clampScoreToVerdictBand/` against the file text and was proved
  // toothless: replacing the clamp with `const score = rawScore` left both
  // green, because the import line alone satisfied the regex.
  it('publishes the clamped score, with the raw preserved', async () => {
    const { buildPublishPayload } = await import('../../src/registry/publish');
    const payload = buildPublishPayload({
      packageName: 'p',
      packageType: 'npm',
      packageVersion: '1.0.0',
      hardeningFindings: [
        { checkId: 'X-1', name: 'x', severity: 'high', passed: false, category: 'other', message: '' },
      ],
    } as any, '0.0.0-test');

    // Non-vacuity: the input must actually land in the good band pre-clamp,
    // or "score < 70" proves nothing.
    expect(payload.rawScore, 'raw composite is not in the good band').toBeGreaterThanOrEqual(GOOD_BAND_FLOOR);
    expect(payload.score).toBe(VERDICT_FAIL_CLAMP);
    expect(payload.scoreClamped).toBe(true);
    expect(payload.verdict).toBe('fail');
  });

  it('omits the raw fields entirely when nothing was clamped', async () => {
    const { buildPublishPayload } = await import('../../src/registry/publish');
    const payload = buildPublishPayload({
      packageName: 'p',
      packageType: 'npm',
      packageVersion: '1.0.0',
      hardeningFindings: [],
    } as any, '0.0.0-test');
    expect(payload.score).toBe(100);
    expect(payload).not.toHaveProperty('scoreClamped');
    expect(payload).not.toHaveProperty('rawScore');
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
