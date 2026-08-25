/**
 * #458 step 0 — `calculateRating` over `number | null` levels.
 *
 * A level with a zero scored denominator arrives as `null` (never 100, never
 * 0). A rung of the ladder that reads a null level is UNAVAILABLE: skipped,
 * not failed. The first available rung that holds is awarded. When every
 * rung reads a null (L1 is null) the rating is `Not Assessed`.
 *
 * `0` is a measurement (0 of N passed) and keeps failing rungs exactly as
 * before; the pins below hold that line.
 *
 * Cells tagged RED-ON-BASE fail on the 6d6685e build, where a null L1 fell
 * through every comparison to `Not Passing` (JS: `null === 100`,
 * `null >= 90`, `null >= 70` are all false), a null L2/L3 fell to `Passing`,
 * and the ladder had no way to say "not measured".
 */
import { describe, it, expect } from 'vitest';
import * as oasb from '../../src/benchmarks/oasb-1';
import * as pkg from '../../src/index';
import { hasDisplayHazard } from '../../src/ui/display-safe';

const { calculateRating } = oasb;

describe('calculateRating: null levels are skipped rungs, not failed ones', () => {
  it('RED-ON-BASE L1 null is Not Assessed at every requested level (every rung reads L1)', () => {
    expect(calculateRating(null, null, null, 'L1')).toBe('Not Assessed');
    expect(calculateRating(null, null, null, 'L2')).toBe('Not Assessed');
    expect(calculateRating(null, 100, 100, 'L3')).toBe('Not Assessed');
  });

  it('RED-ON-BASE a null L1 is never Not Passing', () => {
    for (const level of ['L1', 'L2', 'L3'] as const) {
      expect(calculateRating(null, 0, 0, level)).not.toBe('Not Passing');
    }
  });

  it('L1 ladder never reads L2/L3: nulls there do not move an L1 rating', () => {
    expect(calculateRating(100, null, null, 'L1')).toBe('Certified');
    expect(calculateRating(90, null, null, 'L1')).toBe('Passing');
    expect(calculateRating(70, null, null, 'L1')).toBe('Needs Improvement');
    expect(calculateRating(69, null, null, 'L1')).toBe('Not Passing');
  });

  it('L2 requested, L2 null: Certified and Compliant are unavailable; Passing/Needs Improvement/Not Passing decide on L1', () => {
    expect(calculateRating(100, null, null, 'L2')).toBe('Passing');
    expect(calculateRating(90, null, null, 'L2')).toBe('Passing');
    expect(calculateRating(75, null, null, 'L2')).toBe('Needs Improvement');
    expect(calculateRating(69, null, null, 'L2')).toBe('Not Passing');
  });

  it('L2 requested, L2 measured: unchanged ladder', () => {
    expect(calculateRating(100, 100, null, 'L2')).toBe('Certified');
    expect(calculateRating(100, 90, null, 'L2')).toBe('Compliant');
    expect(calculateRating(100, 50, null, 'L2')).toBe('Passing');
  });

  it('L3 requested: Certified needs a measured L3; Compliant needs a measured L2; the rest read L1', () => {
    expect(calculateRating(100, 100, null, 'L3')).toBe('Compliant');
    expect(calculateRating(100, null, null, 'L3')).toBe('Passing');
    expect(calculateRating(94, 100, null, 'L3')).toBe('Passing');
    expect(calculateRating(100, 100, 100, 'L3')).toBe('Certified');
    expect(calculateRating(100, null, 100, 'L3')).toBe('Passing');
  });

  it('L3 requested with L2/L3 null: the fail words still decide on the measured L1 (pre-mortem 2)', () => {
    expect(calculateRating(60, null, null, 'L3')).toBe('Not Passing');
    expect(calculateRating(85, null, null, 'L3')).toBe('Needs Improvement');
    expect(calculateRating(100, 50, null, 'L3')).toBe('Passing');
  });

  it('PIN: 0 is a measurement, not an absence — it still fails the rungs it always failed', () => {
    expect(calculateRating(0, 0, 0, 'L1')).toBe('Not Passing');
    expect(calculateRating(100, 0, 0, 'L2')).toBe('Passing');
    expect(calculateRating(100, 100, 0, 'L3')).toBe('Compliant');
  });
});

describe('ratingsUnavailableWhenNull: which words a null level takes off the table', () => {
  // The render derives its "X and Y are not awardable" clause from the same
  // rung table `calculateRating` walks, so the prose cannot drift from the
  // arithmetic.
  const unavailable = (level: oasb.BenchmarkLevel, nullLevel: oasb.BenchmarkLevel) =>
    oasb.ratingsUnavailableWhenNull(level, nullLevel);

  it('RED-ON-BASE at L3, a null L3 removes Certified only', () => {
    expect(unavailable('L3', 'L3')).toEqual(['Certified']);
  });

  it('RED-ON-BASE at L3 or L2, a null L2 removes Certified and Compliant', () => {
    expect(unavailable('L3', 'L2')).toEqual(['Certified', 'Compliant']);
    expect(unavailable('L2', 'L2')).toEqual(['Certified', 'Compliant']);
  });

  it('RED-ON-BASE a null L1 removes every word at every level', () => {
    for (const level of ['L1', 'L2', 'L3'] as const) {
      const words = unavailable(level, 'L1');
      expect(words).toContain('Certified');
      expect(words).toContain('Passing');
      expect(words).toContain('Needs Improvement');
      expect(words).toContain('Not Passing');
      expect(words).not.toContain('Not Assessed');
    }
  });

  it('RED-ON-BASE a level the ladder does not read removes nothing', () => {
    expect(unavailable('L1', 'L2')).toEqual([]);
    expect(unavailable('L1', 'L3')).toEqual([]);
    expect(unavailable('L2', 'L3')).toEqual([]);
  });

  it('PROPERTY: the ladder never awards a word that ratingsUnavailableWhenNull says a null level removes', () => {
    // Derived from the same rung table both functions walk: with every
    // measured level at 100 and exactly one level null, the awarded word
    // must not be in the unavailable list, and must be the strongest word
    // that is left.
    const levels: oasb.BenchmarkLevel[] = ['L1', 'L2', 'L3'];
    for (const level of levels) {
      for (const nullLevel of levels) {
        const v = (lv: oasb.BenchmarkLevel): number | null => (lv === nullLevel ? null : 100);
        const word = calculateRating(v('L1'), v('L2'), v('L3'), level);
        const removed = unavailable(level, nullLevel);
        expect(removed, `${level} with ${nullLevel} null awarded ${word}`).not.toContain(word);
        const all = unavailable(level, 'L1'); // the whole ladder at this level, strongest first
        const left = all.filter((w) => !removed.includes(w));
        expect(word).toBe(left.length === 0 ? 'Not Assessed' : left[0]);
      }
    }
  });
});

describe('nextLevelFooter: derived from the catalogue, not from a literal', () => {
  const control = (id: string, level: oasb.BenchmarkLevel, checkIds: string[]): oasb.BenchmarkControl => ({
    id, name: `control ${id}`, category: 'Stub', level, scored: true, description: '',
    checkIds, verification: checkIds.length > 0 ? 'automated' : 'forward',
  });
  const stub = (controls: oasb.BenchmarkControl[]): oasb.BenchmarkCategory[] => [{ id: 1, name: 'Stub', description: '', controls }];

  it('cites the next level while an automated check there can change the rating', () => {
    const cat = stub([control('1.1', 'L1', ['A']), control('1.2', 'L2', ['B']), control('1.3', 'L3', ['C'])]);
    expect(oasb.nextLevelFooter('L1', 'hma', cat)).toBe("Run 'hma secure -b oasb-1 -l L2' for stricter checks.");
    expect(oasb.nextLevelFooter('L2', 'hma', cat)).toBe("Run 'hma secure -b oasb-1 -l L3' for hardened requirements.");
    expect(oasb.nextLevelFooter('L3', 'hma', cat)).toBeNull();
  });

  it('states the fact and cites no command while the next level has no automated check', () => {
    const cat = stub([control('1.1', 'L1', ['A']), control('1.2', 'L2', []), control('1.3', 'L3', []), control('1.4', 'L3', [])]);
    expect(oasb.nextLevelFooter('L1', 'hma', cat)).toBe('L2 adds 1 control (1.2); none has an automated check in this version, so -l L2 cannot raise this rating.');
    expect(oasb.nextLevelFooter('L2', 'hma', cat)).toBe('L3 adds 2 controls (1.3, 1.4); none has an automated check in this version, so -l L3 cannot raise this rating.');
    expect(oasb.nextLevelFooter('L2', 'hma', cat)).not.toContain('Run ');
  });

  it('RED-ON-BASE with the shipped catalogue: L1 -> cites -l L2; L2 -> states the L3 fact (3.5, 8.4)', () => {
    expect(oasb.nextLevelFooter('L1', 'hackmyagent')).toContain("-l L2' for stricter checks");
    expect(oasb.nextLevelFooter('L2', 'hackmyagent')).toBe('L3 adds 2 controls (3.5, 8.4); none has an automated check in this version, so -l L3 cannot raise this rating.');
    expect(oasb.automatedControlsAt('L3').length).toBe(0);
    expect(oasb.automatedControlsAt('L2').length).toBe(3);
    // 23 L1 controls carry checkIds; one of them is not `verification: 'automated'`
    // and so cannot settle on its own, which is the census this helper takes.
    expect(oasb.automatedControlsAt('L1').length).toBe(22);
  });
});

describe('#458 step 0 library surface', () => {
  it('RED-ON-BASE the three helpers beside calculateRating are exported from the package root', () => {
    for (const name of ['ratingsUnavailableWhenNull', 'automatedControlsAt', 'nextLevelFooter'] as const) {
      expect(typeof (pkg as any)[name], name).toBe('function');
    }
    expect(pkg.calculateRating(null, null, null, 'L1')).toBe('Not Assessed');
  });

  it('PIN: no catalogue category name carries a display hazard (the cited -c value is one of these)', () => {
    for (const c of oasb.OASB_1_CATEGORIES) {
      expect(hasDisplayHazard(c.name), c.name).toBe(false);
    }
  });
});
