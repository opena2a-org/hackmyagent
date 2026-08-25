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
import { countsAgainstScore, retainForVerdict } from '../../src/ui/verdict-band';

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
