/**
 * Tests for OASB v2 governance remediation templates.
 */

import { describe, it, expect } from 'vitest';
import {
  getRemediation,
  getRemediations,
  getAllRemediations,
  getRemediationCount,
  getRemediationIds,
} from '../../src/abgr/templates';
import { ALL_GOVERNANCE_CONTROLS } from '../../src/abgr/controls';

describe('getRemediationCount', () => {
  it('returns 68 (one per control)', () => {
    expect(getRemediationCount()).toBe(68);
  });
});

describe('getRemediationIds', () => {
  it('returns 68 IDs', () => {
    expect(getRemediationIds()).toHaveLength(68);
  });

  it('every ID matches a control', () => {
    const controlIds = new Set(ALL_GOVERNANCE_CONTROLS.map(c => c.id));
    for (const id of getRemediationIds()) {
      expect(controlIds.has(id)).toBe(true);
    }
  });

  it('every control has a template', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(getRemediationIds()).toContain(control.id);
    }
  });
});

describe('getRemediation', () => {
  it('returns a template for TH-001', () => {
    const template = getRemediation('TH-001');
    expect(template).toBeDefined();
    expect(template!.length).toBeGreaterThan(0);
  });

  it('returns undefined for an invalid ID', () => {
    expect(getRemediation('INVALID-999')).toBeUndefined();
  });

  it('templates are valid markdown (contain heading or content)', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      const template = getRemediation(control.id);
      expect(template).toBeDefined();
      // Each template should have meaningful content
      expect(template!.length).toBeGreaterThan(20);
    }
  });

  it('every template contains a markdown heading', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      const template = getRemediation(control.id);
      expect(template).toBeDefined();
      // Each template should start with a ## or ### heading
      expect(template!).toMatch(/^#{2,3}\s+/m);
    }
  });
});

describe('getRemediations', () => {
  it('returns concatenated templates for multiple IDs', () => {
    const result = getRemediations(['TH-001', 'TH-002']);
    expect(result).toBeTruthy();
    expect(result.length).toBeGreaterThan(0);
    // Should contain content from both templates
    const t1 = getRemediation('TH-001')!;
    const t2 = getRemediation('TH-002')!;
    expect(result).toContain(t1);
    expect(result).toContain(t2);
  });

  it('skips invalid IDs without error', () => {
    const result = getRemediations(['TH-001', 'INVALID-999']);
    const t1 = getRemediation('TH-001')!;
    expect(result).toContain(t1);
  });

  it('returns empty string for empty input', () => {
    expect(getRemediations([])).toBe('');
  });

  it('returns all 68 templates when given all IDs', () => {
    const allIds = getRemediationIds();
    const result = getRemediations(allIds);
    // Should contain content from all templates
    expect(result.length).toBeGreaterThan(1000);
  });
});

describe('getAllRemediations', () => {
  it('returns all templates concatenated', () => {
    const all = getAllRemediations();
    expect(all.length).toBeGreaterThan(1000);
    // Spot-check: should contain content from first and last domain templates
    expect(all).toContain('Trust');
    expect(all).toContain('Override');
  });
});
