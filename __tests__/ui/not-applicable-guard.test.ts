/**
 * #458 — a not-applicable record (`notApplicable` set, `passed` omitted) is
 * neither an outstanding failure nor a verdict line.
 *
 * Red on c0ee1f7 (measured, this file against that verdict-band.ts):
 * `countsAgainstScore({ notApplicable })` was true — `!f.fixed` alone — and
 * `retainForVerdict({ notApplicable })` was true — `!f.passed` alone. The third
 * state fell into "failed" on both readers, which is the score defect #458
 * names: an absent Dockerfile scored as a failed container check.
 */
import { describe, it, expect } from 'vitest';
import { confirmedFix, countsAgainstScore, retainForVerdict } from '../../src/ui/verdict-band';

const NA = {
  notApplicable: {
    subject: 'Dockerfile',
    reason: 'no Dockerfile in this tree; the container checks measured nothing',
  },
};

describe('#458 not-applicable records do not read as failures', () => {
  it('countsAgainstScore: an NA record does not count against the score', () => {
    expect(countsAgainstScore(NA)).toBe(false);
  });

  it('countsAgainstScore: NA is decided before every other field', () => {
    // fixed + fixVerified:false is the one shape that counts even when fixed;
    // NA still wins, so the guard cannot be moved below that clause.
    expect(countsAgainstScore({ ...NA, fixed: true, fixVerified: false })).toBe(false);
  });

  it('retainForVerdict: an NA record is not a verdict line', () => {
    expect(retainForVerdict(NA)).toBe(false);
    expect(retainForVerdict({ ...NA, fixed: true })).toBe(false);
  });

  it('the two measured states are unchanged', () => {
    expect(countsAgainstScore({ passed: false })).toBe(true);
    expect(countsAgainstScore({ passed: true })).toBe(false);
    expect(countsAgainstScore({ passed: false, fixed: true })).toBe(false);
    expect(countsAgainstScore({ passed: false, fixed: true, fixVerified: false })).toBe(true);
    expect(retainForVerdict({ passed: false })).toBe(true);
    expect(retainForVerdict({ passed: true })).toBe(false);
    expect(retainForVerdict({ passed: true, fixed: true })).toBe(true);
  });
});

describe('#458 confirmedFix: an NA record is never a confirmed fix', () => {
  // This is the one predicate where the NA short-circuit in
  // `countsAgainstScore` INVERTS instead of composing: NA makes
  // `countsAgainstScore` false, so `!countsAgainstScore(f)` reads "not an
  // issue" as "confirmed" and a stray `fixed: true` on an NA record would be
  // published as a remediation (src/registry/remediation.ts:37). Red on
  // 4f02a0a (measured): `confirmedFix({ ...NA, fixed: true })` was true.
  it('NA alone is not a confirmed fix', () => {
    expect(confirmedFix(NA)).toBe(false);
  });

  it('NA + stray fixed:true is not a confirmed fix', () => {
    expect(confirmedFix({ ...NA, fixed: true })).toBe(false);
    expect(confirmedFix({ ...NA, fixed: true, fixVerified: true })).toBe(false);
  });

  it('NA is in no bucket across the whole {passed,fixed,fixVerified} space', () => {
    const tri = [true, false, undefined] as const;
    for (const passed of tri) for (const fixed of tri) for (const fixVerified of tri) {
      const f = { ...NA, passed, fixed, fixVerified };
      const label = JSON.stringify({ passed, fixed, fixVerified });
      expect(countsAgainstScore(f), label).toBe(false);
      expect(retainForVerdict(f), label).toBe(false);
      expect(confirmedFix(f), label).toBe(false);
    }
  });
});
