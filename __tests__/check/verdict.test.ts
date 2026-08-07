/**
 * #373 — the verdict and its exit code come out of one derivation.
 *
 * Unit half. The spawn half lives in
 * `__tests__/cli/check-json-exit-parity.test.ts`; this one gates the rule
 * itself in every CI run, including the runners where the built CLI is
 * absent.
 *
 * The property under test is an EQUIVALENCE, not two independent facts: the
 * exit code must be derivable from the reported `risk` and nothing else.
 * Pre-fix, `check` computed the identical `risk` expression in both output
 * branches and then only one of them reached an exit statement, so the two
 * agreed by coincidence of code placement rather than by construction.
 */
import { describe, it, expect } from 'vitest';
import { deriveCheckVerdict, type CheckRisk } from '../../src/check/verdict';

/** `check --help`: "Exit code 1 if high/critical risk detected." */
const FAILING_BANDS: readonly CheckRisk[] = ['critical', 'high'];

describe('#373 deriveCheckVerdict', () => {
  const cases: Array<{
    label: string;
    counts: { critical: number; high: number; issues?: number };
    risk: CheckRisk;
    exitCode: 0 | 1;
  }> = [
    { label: 'nothing found', counts: { critical: 0, high: 0, issues: 0 }, risk: 'low', exitCode: 0 },
    { label: 'medium/low only', counts: { critical: 0, high: 0, issues: 3 }, risk: 'medium', exitCode: 0 },
    { label: 'one high', counts: { critical: 0, high: 1, issues: 1 }, risk: 'high', exitCode: 1 },
    { label: 'one critical', counts: { critical: 1, high: 0, issues: 1 }, risk: 'critical', exitCode: 1 },
    { label: 'the measured exfil fixture', counts: { critical: 4, high: 1, issues: 5 }, risk: 'critical', exitCode: 1 },
    // critical outranks high even when high is larger — the band is a
    // maximum, not a majority.
    { label: 'critical outranks a larger high count', counts: { critical: 1, high: 9, issues: 10 }, risk: 'critical', exitCode: 1 },
  ];

  for (const c of cases) {
    it(`${c.label} -> ${c.risk} / exit ${c.exitCode}`, () => {
      expect(deriveCheckVerdict(c.counts)).toEqual({ risk: c.risk, exitCode: c.exitCode });
    });
  }

  it('derives the exit code from the risk band for every input, not per branch', () => {
    // Sweeps the whole small input space rather than the six rows above, so a
    // future edit cannot satisfy the table while breaking an untabled
    // combination. `issues` is swept independently of critical/high because
    // it is the only field that separates `medium` from `low`, and a call
    // site that forgets to pass it is the realistic regression.
    for (let critical = 0; critical <= 3; critical++) {
      for (let high = 0; high <= 3; high++) {
        for (const issues of [undefined, 0, 1, 7]) {
          const v = deriveCheckVerdict({ critical, high, issues });
          expect(
            v.exitCode,
            `critical=${critical} high=${high} issues=${issues} reported risk=${v.risk} `
            + `but exit=${v.exitCode}; the exit code must follow the band`,
          ).toBe(FAILING_BANDS.includes(v.risk) ? 1 : 0);
        }
      }
    }
  });

  it('omitting `issues` cannot understate the band', () => {
    // The remote target paths do not count MEDIUM/LOW separately, so they
    // call this without `issues`. That may understate `medium` as `low` —
    // which changes no exit code — but it must never turn a failing band
    // into a passing one.
    for (let critical = 0; critical <= 3; critical++) {
      for (let high = 0; high <= 3; high++) {
        const withIssues = deriveCheckVerdict({ critical, high, issues: critical + high });
        const without = deriveCheckVerdict({ critical, high });
        expect(without.exitCode).toBe(withIssues.exitCode);
      }
    }
  });

  it('a clean target does not fail', () => {
    // The other direction. A guard that exits 1 on everything would satisfy
    // every assertion above about malicious input.
    expect(deriveCheckVerdict({ critical: 0, high: 0, issues: 0 })).toEqual({ risk: 'low', exitCode: 0 });
  });
});
