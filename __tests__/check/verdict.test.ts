/**
 * #373 — the verdict and its exit code come out of one derivation.
 * #406/#430/#417/#416/#390 — and neither can exist without a measurement.
 *
 * Unit half. The spawn half lives in
 * `__tests__/cli/check-json-exit-parity.test.ts` and
 * `__tests__/cli/verdict-requires-measurement.test.ts`; this one gates the
 * rules themselves in every CI run, including the runners where the built CLI
 * is absent.
 *
 * The #373 property under test is an EQUIVALENCE, not two independent facts:
 * the exit code must be derivable from the reported `risk` and nothing else.
 * Pre-fix, `check` computed the identical `risk` expression in both output
 * branches and then only one of them reached an exit statement, so the two
 * agreed by coincidence of code placement rather than by construction.
 *
 * The measurement property is a DOMAIN restriction: a risk band may only be
 * derived over coverage that examined something. Pre-fix, zero findings over
 * zero examined units produced `low` / exit 0, which is how an unreachable
 * endpoint scored `0/100 (SECURE)`.
 */
import { describe, it, expect } from 'vitest';
import {
  deriveCheckVerdict,
  unmeasured,
  fullCoverage,
  coverageJson,
  unmeasuredBanner,
  EXIT_PASS,
  EXIT_FAIL,
  EXIT_UNMEASURED,
  type CheckRisk,
  type Coverage,
} from '../../src/check/verdict';

/** `check --help`: "Exit code 1 if high/critical risk detected." */
const FAILING_BANDS: readonly CheckRisk[] = ['critical', 'high'];

/** Any non-empty measurement. The band must not depend on its magnitude. */
const SOME: Coverage = fullCoverage(7, 'file');

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
      expect(deriveCheckVerdict(c.counts, SOME)).toEqual({
        measured: true,
        risk: c.risk,
        coverage: SOME,
        exitCode: c.exitCode,
      });
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
          const v = deriveCheckVerdict({ critical, high, issues }, SOME);
          if (!v.measured) throw new Error('a non-empty coverage must produce a band');
          expect(
            v.exitCode,
            `critical=${critical} high=${high} issues=${issues} reported risk=${v.risk} `
            + `but exit=${v.exitCode}; the exit code must follow the band`,
          ).toBe(FAILING_BANDS.includes(v.risk) ? EXIT_FAIL : EXIT_PASS);
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
        const withIssues = deriveCheckVerdict({ critical, high, issues: critical + high }, SOME);
        const without = deriveCheckVerdict({ critical, high }, SOME);
        expect(without.exitCode).toBe(withIssues.exitCode);
      }
    }
  });

  it('a clean target does not fail', () => {
    // The other direction. A guard that exits 1 on everything would satisfy
    // every assertion above about malicious input.
    expect(deriveCheckVerdict({ critical: 0, high: 0, issues: 0 }, SOME)).toEqual({
      measured: true,
      risk: 'low',
      coverage: SOME,
      exitCode: EXIT_PASS,
    });
  });

  it('the band does not move with the size of the measurement', () => {
    // #430's shape, at the unit level: the score moved with `--intensity` and
    // never with the target. Coverage is evidence that a band may be reported,
    // not an input to which band it is.
    const bands = [1, 2, 50, 111].map(
      n => deriveCheckVerdict({ critical: 0, high: 1, issues: 1 }, fullCoverage(n, 'payload')),
    );
    for (const v of bands) {
      if (!v.measured) throw new Error('non-empty coverage must produce a band');
      expect(v.risk).toBe('high');
      expect(v.exitCode).toBe(EXIT_FAIL);
    }
  });
});

describe('#406/#430 a band cannot be derived over an empty measurement', () => {
  it('zero examined units yields unmeasured, not `low`', () => {
    // The exact pre-fix shape: no findings, nothing examined. This returned
    // `{risk:"low", exitCode:0}`, which `attack` rendered as `0/100 (SECURE)`.
    const v = deriveCheckVerdict({ critical: 0, high: 0, issues: 0 }, fullCoverage(0, 'payload'));
    expect(v.measured).toBe(false);
    expect(v.exitCode).toBe(EXIT_UNMEASURED);
    expect(v).not.toHaveProperty('risk');
  });

  it('holds for every severity count, not only the clean one', () => {
    // A caller cannot buy a band by reporting findings it did not measure
    // either. Sweeps both directions so a fix that special-cased "0 findings
    // and 0 coverage" would still fail here.
    for (let critical = 0; critical <= 2; critical++) {
      for (let high = 0; high <= 2; high++) {
        for (const issues of [undefined, 0, 5]) {
          const v = deriveCheckVerdict({ critical, high, issues }, { examined: 0, total: 111, unit: 'payload' });
          expect(
            v.measured,
            `critical=${critical} high=${high} issues=${issues} over 0 examined must be unmeasured`,
          ).toBe(false);
          expect(v.exitCode).toBe(EXIT_UNMEASURED);
        }
      }
    }
  });

  it('a negative examined count cannot slip past the gate', () => {
    // `<= 0`, not `=== 0`. A caller subtracting two counters can reach -1, and
    // `examined === 0` would have let that through as a measured band.
    const v = deriveCheckVerdict({ critical: 0, high: 0 }, { examined: -1, total: 3, unit: 'file' });
    expect(v.measured).toBe(false);
  });

  it('has no "but we found something" escape hatch', () => {
    // A second-round fix added one — treating any finding as proof the run
    // examined the target — and it punched a hole through the guarantee this
    // file exists to make: a caller with a broken coverage counter would have
    // its band restored by the very findings whose provenance was in doubt.
    //
    // The real defect that motivated it was a wrong coverage UNIT at one call
    // site (files-read for a suite whose checks fire on a file's absence), not
    // a wrong gate. This pins the gate so the hole is not reopened.
    for (const counts of [
      { critical: 9, high: 0, issues: 9 },
      { critical: 0, high: 9, issues: 9 },
      { critical: 0, high: 0, issues: 9 },
    ]) {
      const v = deriveCheckVerdict(counts, fullCoverage(0, 'file'));
      expect(v.measured, `${JSON.stringify(counts)} over 0 coverage must stay unmeasured`).toBe(false);
    }
  });

  it('one examined unit is enough — the gate is emptiness, not a quorum', () => {
    // The opposite direction. A gate that demanded "enough" coverage would
    // silently withhold verdicts on small but real targets, which is a
    // different defect with the same output.
    const v = deriveCheckVerdict({ critical: 0, high: 0, issues: 0 }, fullCoverage(1, 'file'));
    expect(v.measured).toBe(true);
    expect(v.exitCode).toBe(EXIT_PASS);
  });

  it('carries the caller\'s reason and detail through', () => {
    const v = deriveCheckVerdict(
      { critical: 0, high: 0 },
      fullCoverage(0, 'payload'),
      'target-unreachable',
      'nothing answered',
    );
    expect(v).toEqual({
      measured: false,
      reason: 'target-unreachable',
      detail: 'nothing answered',
      attempted: { examined: 0, total: 0, unit: 'payload' },
      exitCode: EXIT_UNMEASURED,
    });
  });

  it('keeps what was attempted, so 0-of-111 is distinguishable from 0-of-0', () => {
    // Adversarial review finding: the unmeasured arm carried no coverage, so
    // `coverageJson` flattened every unmeasured run to `0/0 unit`. A suite that
    // sent 111 payloads and had none answered then serialized identically to a
    // run that never started, under a unit no caller used.
    const sent111 = deriveCheckVerdict(
      { critical: 0, high: 0 },
      { examined: 0, total: 111, unit: 'payload' },
      'no-response',
      'nothing answered',
    );
    const neverStarted = unmeasured('target-unreachable', 'nothing was sent');

    expect(coverageJson(sent111)).toMatchObject({ measured: false, examined: 0, total: 111, unit: 'payload' });
    expect(coverageJson(neverStarted)).toMatchObject({ measured: false, examined: 0, total: 0 });
    expect(coverageJson(sent111)).not.toEqual(coverageJson(neverStarted));
  });
});

describe('the three exit codes are distinct and mean one thing each', () => {
  it('0, 1 and 2 are not aliases', () => {
    // A refactor that collapsed "not measured" back into "clean" would restore
    // #406 exactly, and every other assertion here would still pass.
    expect(new Set([EXIT_PASS, EXIT_FAIL, EXIT_UNMEASURED]).size).toBe(3);
    expect(EXIT_UNMEASURED).not.toBe(EXIT_PASS);
  });

  it('unmeasured is non-zero, so a CI job cannot read it as a pass', () => {
    expect(unmeasured('target-not-found', 'x').exitCode).toBeGreaterThan(0);
  });
});

describe('the machine and text channels report the same measurement', () => {
  it('coverageJson mirrors a measured verdict', () => {
    const v = deriveCheckVerdict({ critical: 0, high: 0 }, { examined: 4, total: 111, unit: 'payload' });
    expect(coverageJson(v)).toEqual({ measured: true, examined: 4, total: 111, unit: 'payload' });
  });

  it('coverageJson names the reason on an unmeasured verdict', () => {
    const v = unmeasured('simulation-only', 'no agent was contacted');
    expect(coverageJson(v)).toMatchObject({
      measured: false,
      examined: 0,
      reason: 'simulation-only',
      detail: 'no agent was contacted',
    });
  });

  it('the banner is empty exactly when the run measured', () => {
    // So a renderer cannot print "NOT MEASURED" over a real result, nor stay
    // silent over an unmeasured one.
    expect(unmeasuredBanner(deriveCheckVerdict({ critical: 0, high: 0 }, SOME))).toBe('');
    expect(unmeasuredBanner(unmeasured('no-response', 'nothing answered')))
      .toContain('NOT MEASURED');
  });

  it('the two channels never disagree about whether a run measured', () => {
    for (const v of [
      deriveCheckVerdict({ critical: 2, high: 0 }, SOME),
      deriveCheckVerdict({ critical: 0, high: 0 }, fullCoverage(0, 'file')),
      unmeasured('target-not-found', 'gone'),
    ]) {
      expect(coverageJson(v).measured).toBe(v.measured);
      expect(unmeasuredBanner(v) === '').toBe(v.measured);
      expect(v.exitCode === EXIT_UNMEASURED).toBe(!v.measured);
    }
  });
});
