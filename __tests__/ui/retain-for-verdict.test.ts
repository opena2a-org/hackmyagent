/**
 * #285 — the report-retention filter and the score predicate must agree.
 *
 * `src/cli.ts` re-filters `result.findings` and then computes the score over
 * what survives. If the filter drops something `countsAgainstScore` counts, the
 * score is computed from a list the finding was already removed from: #259,
 * where a GIT-002 HIGH clamped the score to 69 and then appeared in no finding
 * block, no category summary and no verdict — the number saying fail-direction
 * and every word beside it saying the opposite.
 *
 * The rule lived as five identical inline copies (the `secure` path plus four
 * NanoMind merge blocks). Measured on `d9e4ee1`: mutating the four NanoMind
 * copies to `!f.passed` and rebuilding left the suite green at 221 files /
 * 2886 tests, because only the `secure` copy was reachable from a test.
 *
 * The test below is a PROPERTY over the whole input space rather than a restatement
 * of the implementation. Asserting `retainForVerdict({passed:false}) === true`
 * would just be the source copied into the test file; the invariant that
 * actually matters is the relationship between the two predicates.
 */
import { describe, it, expect } from 'vitest';
import { countsAgainstScore, retainForVerdict } from '../../src/ui/verdict-band';

/** Every combination of the three fields the two predicates read. */
const SPACE = (() => {
  const tri = [true, false, undefined] as const;
  const out: Array<{ passed?: boolean; fixed?: boolean; fixVerified?: boolean }> = [];
  for (const passed of tri) for (const fixed of tri) for (const fixVerified of tri) {
    out.push({ passed, fixed, fixVerified });
  }
  return out;
})();

const show = (f: object) => JSON.stringify(f);

describe('#285 retention and scoring agree', () => {
  it('covers the whole input space', () => {
    // Non-vacuity: a generator that produced nothing would make the property
    // below trivially true.
    expect(SPACE).toHaveLength(27);
  });

  it('never drops a finding that counts against the score', () => {
    // THE invariant. Any narrowing of the retention filter — `!f.passed`, or
    // dropping the `fixed` half — violates it for the disproved-fix shape.
    const violations = SPACE.filter((f) => countsAgainstScore(f) && !retainForVerdict(f));
    expect(violations.map(show), 'a counted finding would be filtered out before scoring').toEqual([]);
  });

  it('is not vacuous: the space contains findings that DO count', () => {
    // If nothing counted, "never drops a counted finding" would hold for a
    // predicate that returns false always.
    expect(SPACE.filter((f) => countsAgainstScore(f)).length).toBeGreaterThan(0);
  });

  it('is not the trivial always-true filter', () => {
    // The other direction: retention must still exclude something, or the
    // re-filter has stopped doing its job.
    expect(SPACE.filter((f) => !retainForVerdict(f)).length).toBeGreaterThan(0);
  });

  it('retains the shape the twelve `passed: <check>Fixed` checks produce', () => {
    // Named explicitly because this is the one that regressed in #259 and the
    // one every naive `!f.passed` rewrite loses.
    const disproved = { passed: true, fixed: true, fixVerified: false };
    expect(countsAgainstScore(disproved)).toBe(true);
    expect(retainForVerdict(disproved)).toBe(true);
  });

  it('drops an ordinary passing check', () => {
    expect(retainForVerdict({ passed: true })).toBe(false);
    expect(countsAgainstScore({ passed: true })).toBe(false);
  });
});
