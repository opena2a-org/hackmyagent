/**
 * OASB-1 Benchmark Tests
 */

import { describe, it, expect } from 'vitest';
import {
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  getCheckIdsForLevel,
  calculateRating,
  type BenchmarkControl,
  type BenchmarkLevel,
} from './oasb-1';

describe('OASB-1 Benchmark', () => {
  // Flatten all controls for convenience
  const allControls = OASB_1_CATEGORIES.flatMap((cat) => cat.controls);

  describe('benchmark metadata', () => {
    it('has correct version', () => {
      expect(OASB_1_VERSION).toBe('1.0.0');
    });

    it('has correct name', () => {
      expect(OASB_1_NAME).toBe('OASB-1: Open Agent Security Benchmark');
    });
  });

  describe('control definitions', () => {
    it('has 46 total controls', () => {
      expect(allControls.length).toBe(46);
    });

    it('has 10 categories', () => {
      expect(OASB_1_CATEGORIES.length).toBe(10);
    });

    it('all controls have required fields', () => {
      for (const control of allControls) {
        expect(control.id).toBeTruthy();
        expect(control.name).toBeTruthy();
        expect(control.category).toBeTruthy();
        expect(control.level).toBeTruthy();
        expect(typeof control.scored).toBe('boolean');
        expect(control.description).toBeTruthy();
        expect(Array.isArray(control.checkIds)).toBe(true);
        expect(['automated', 'manual', 'forward']).toContain(control.verification);
      }
    });

    it('all control IDs are unique', () => {
      const ids = allControls.map((c) => c.id);
      const uniqueIds = new Set(ids);
      expect(ids.length).toBe(uniqueIds.size);
    });

    it('level distribution is L1=26, L2=18, L3=2', () => {
      const l1 = allControls.filter((c) => c.level === 'L1').length;
      const l2 = allControls.filter((c) => c.level === 'L2').length;
      const l3 = allControls.filter((c) => c.level === 'L3').length;
      expect(l1).toBe(26);
      expect(l2).toBe(18);
      expect(l3).toBe(2);
    });

    it('all checkIds follow known prefixes', () => {
      const validPrefixes = [
        'CRED-', 'TOOL-', 'PROMPT-', 'IO-', 'NET-', 'DEP-',
        'LOG-', 'AUDIT-', 'PERM-', 'RATE-', 'SANDBOX-',
        'MCP-', 'PROC-', 'ENV-', 'SEM-',
      ];
      for (const control of allControls) {
        for (const checkId of control.checkIds) {
          const hasValidPrefix = validPrefixes.some((prefix) => checkId.startsWith(prefix));
          expect(hasValidPrefix, `${control.id} has invalid checkId prefix: ${checkId}`).toBe(true);
        }
      }
    });

    it('automated controls with checkIds should have at least one checkId', () => {
      for (const control of allControls) {
        if (control.verification === 'automated') {
          expect(
            control.checkIds.length,
            `${control.id} (${control.name}) is automated but has no checkIds`
          ).toBeGreaterThan(0);
        }
      }
    });

    it('manual and forward controls have empty checkIds or only semantic checkIds', () => {
      for (const control of allControls) {
        if (control.verification === 'manual' || control.verification === 'forward') {
          // Semantic engine checkIds (SEM-*) are allowed on forward controls
          // because they provide partial automated verification
          const nonSemanticIds = control.checkIds.filter((id) => !id.startsWith('SEM-'));
          expect(
            nonSemanticIds.length,
            `${control.id} is ${control.verification} but has non-semantic checkIds: ${nonSemanticIds.join(', ')}`
          ).toBe(0);
        }
      }
    });

    it('control category matches parent category', () => {
      for (const category of OASB_1_CATEGORIES) {
        for (const control of category.controls) {
          expect(control.category).toBe(category.name);
        }
      }
    });

    it('category IDs are sequential from 1 to 10', () => {
      const ids = OASB_1_CATEGORIES.map((c) => c.id);
      expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });

    it('expected categories are present', () => {
      const names = OASB_1_CATEGORIES.map((c) => c.name);
      expect(names).toContain('Identity & Provenance');
      expect(names).toContain('Capability & Authorization');
      expect(names).toContain('Input Security');
      expect(names).toContain('Output Security');
      expect(names).toContain('Credential Protection');
      expect(names).toContain('Supply Chain Integrity');
      expect(names).toContain('Agent-to-Agent Security');
      expect(names).toContain('Memory & Context Integrity');
      expect(names).toContain('Operational Security');
      expect(names).toContain('Monitoring & Response');
    });
  });

  describe('getControlsForLevel', () => {
    it('L1 returns only L1 controls', () => {
      const controls = getControlsForLevel('L1');
      expect(controls.length).toBe(26);
      expect(controls.every((c) => c.level === 'L1')).toBe(true);
    });

    it('L2 returns L1 + L2 controls', () => {
      const controls = getControlsForLevel('L2');
      expect(controls.length).toBe(44);
      const levels = new Set(controls.map((c) => c.level));
      expect(levels.has('L1')).toBe(true);
      expect(levels.has('L2')).toBe(true);
      expect(levels.has('L3')).toBe(false);
    });

    it('L3 returns all controls', () => {
      const controls = getControlsForLevel('L3');
      expect(controls.length).toBe(46);
      const levels = new Set(controls.map((c) => c.level));
      expect(levels.has('L1')).toBe(true);
      expect(levels.has('L2')).toBe(true);
      expect(levels.has('L3')).toBe(true);
    });
  });

  describe('getControlsForCategory', () => {
    it('returns correct controls for Identity & Provenance', () => {
      const controls = getControlsForCategory('Identity & Provenance');
      expect(controls.length).toBe(4);
      expect(controls.every((c) => c.category === 'Identity & Provenance')).toBe(true);
    });

    it('returns correct controls for Input Security', () => {
      const controls = getControlsForCategory('Input Security');
      expect(controls.length).toBe(5);
    });

    it('is case-insensitive', () => {
      const controls = getControlsForCategory('input security');
      expect(controls.length).toBe(5);
    });

    it('returns empty for unknown category', () => {
      const controls = getControlsForCategory('Nonexistent Category');
      expect(controls.length).toBe(0);
    });

    it('returns controls for all 10 categories', () => {
      for (const category of OASB_1_CATEGORIES) {
        const controls = getControlsForCategory(category.name);
        expect(controls.length).toBeGreaterThan(0);
        expect(controls.length).toBe(category.controls.length);
      }
    });
  });

  describe('getCheckIdsForLevel', () => {
    it('L1 returns deduplicated check IDs', () => {
      const checkIds = getCheckIdsForLevel('L1');
      const unique = new Set(checkIds);
      expect(checkIds.length).toBe(unique.size);
    });

    it('L2 includes all L1 check IDs plus L2-specific ones', () => {
      const l1Ids = new Set(getCheckIdsForLevel('L1'));
      const l2Ids = new Set(getCheckIdsForLevel('L2'));
      for (const id of l1Ids) {
        expect(l2Ids.has(id), `L2 should include L1 checkId: ${id}`).toBe(true);
      }
      expect(l2Ids.size).toBeGreaterThanOrEqual(l1Ids.size);
    });

    it('L3 includes all L2 check IDs', () => {
      const l2Ids = new Set(getCheckIdsForLevel('L2'));
      const l3Ids = new Set(getCheckIdsForLevel('L3'));
      for (const id of l2Ids) {
        expect(l3Ids.has(id), `L3 should include L2 checkId: ${id}`).toBe(true);
      }
    });
  });

  describe('calculateRating', () => {
    describe('L1 ratings', () => {
      it('100% → Certified', () => {
        expect(calculateRating(100, 0, 0, 'L1')).toBe('Certified');
      });

      it('90% → Passing', () => {
        expect(calculateRating(90, 0, 0, 'L1')).toBe('Passing');
      });

      it('95% → Passing', () => {
        expect(calculateRating(95, 0, 0, 'L1')).toBe('Passing');
      });

      it('70% → Needs Improvement', () => {
        expect(calculateRating(70, 0, 0, 'L1')).toBe('Needs Improvement');
      });

      it('80% → Needs Improvement', () => {
        expect(calculateRating(80, 0, 0, 'L1')).toBe('Needs Improvement');
      });

      it('50% → Failing', () => {
        expect(calculateRating(50, 0, 0, 'L1')).toBe('Failing');
      });

      it('0% → Failing', () => {
        expect(calculateRating(0, 0, 0, 'L1')).toBe('Failing');
      });

      it('69% → Failing', () => {
        expect(calculateRating(69, 0, 0, 'L1')).toBe('Failing');
      });
    });

    describe('L2 ratings', () => {
      it('L1=100% + L2=100% → Certified', () => {
        expect(calculateRating(100, 100, 0, 'L2')).toBe('Certified');
      });

      it('L1=100% + L2=90% → Compliant', () => {
        expect(calculateRating(100, 90, 0, 'L2')).toBe('Compliant');
      });

      it('L1=100% + L2=95% → Compliant', () => {
        expect(calculateRating(100, 95, 0, 'L2')).toBe('Compliant');
      });

      it('L1=100% + L2=50% → Passing (L1 perfect)', () => {
        // L1=100% but L2 < 90%, so falls through to l1>=90 check
        expect(calculateRating(100, 50, 0, 'L2')).toBe('Passing');
      });

      it('L1=90% → Passing', () => {
        expect(calculateRating(90, 0, 0, 'L2')).toBe('Passing');
      });

      it('L1=70% → Needs Improvement', () => {
        expect(calculateRating(70, 0, 0, 'L2')).toBe('Needs Improvement');
      });

      it('L1=50% → Failing', () => {
        expect(calculateRating(50, 0, 0, 'L2')).toBe('Failing');
      });
    });

    describe('L3 ratings', () => {
      it('all 100% → Certified', () => {
        expect(calculateRating(100, 100, 100, 'L3')).toBe('Certified');
      });

      it('L1=100% L2=90% L3=50% → Compliant', () => {
        expect(calculateRating(100, 90, 50, 'L3')).toBe('Compliant');
      });

      it('L1=90% → Passing', () => {
        expect(calculateRating(90, 0, 0, 'L3')).toBe('Passing');
      });

      it('L1=70% → Needs Improvement', () => {
        expect(calculateRating(70, 0, 0, 'L3')).toBe('Needs Improvement');
      });

      it('L1=50% → Failing', () => {
        expect(calculateRating(50, 0, 0, 'L3')).toBe('Failing');
      });
    });

    describe('boundary conditions', () => {
      it('L2: L1=100% L2=89% is not Compliant (below 90% threshold)', () => {
        // L1=100 but L2=89, so it falls through to l1>=90 → Passing
        expect(calculateRating(100, 89, 0, 'L2')).toBe('Passing');
      });

      it('L1: 89% is not Passing (below 90% threshold)', () => {
        expect(calculateRating(89, 0, 0, 'L1')).toBe('Needs Improvement');
      });

      it('L1: 99% is not Certified (below 100% threshold)', () => {
        expect(calculateRating(99, 0, 0, 'L1')).toBe('Passing');
      });
    });
  });
});
