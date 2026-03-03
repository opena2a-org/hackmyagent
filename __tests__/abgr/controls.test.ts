/**
 * Tests for OASB v2 governance control definitions.
 */

import { describe, it, expect } from 'vitest';
import {
  ALL_GOVERNANCE_CONTROLS,
  DOMAIN_METADATA,
  getControlsByDomain,
  getControlById,
  getControlsForTier,
  getControlsBySeverity,
} from '../../src/abgr/controls';
import type { GovernanceDomain, AgentTier, GovernanceSeverity } from '../../src/abgr/types';

describe('ALL_GOVERNANCE_CONTROLS', () => {
  it('defines exactly 68 controls', () => {
    expect(ALL_GOVERNANCE_CONTROLS).toHaveLength(68);
  });

  it('has no duplicate IDs', () => {
    const ids = ALL_GOVERNANCE_CONTROLS.map(c => c.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('every control has a non-empty id', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(control.id).toBeTruthy();
      expect(control.id.length).toBeGreaterThan(0);
    }
  });

  it('every control has a non-empty name and description', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(control.name).toBeTruthy();
      expect(control.description).toBeTruthy();
    }
  });

  it('every control has at least one keyword group', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(control.keywords.length).toBeGreaterThan(0);
      // Each keyword group should have at least one keyword
      for (const group of control.keywords) {
        expect(group.length).toBeGreaterThan(0);
      }
    }
  });

  it('every control is assigned to at least one tier', () => {
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(control.requiredForTier.length).toBeGreaterThan(0);
    }
  });

  it('every control has a valid severity', () => {
    const validSeverities: GovernanceSeverity[] = ['critical', 'high', 'medium', 'low'];
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(validSeverities).toContain(control.severity);
    }
  });

  it('every control has a valid domain', () => {
    const validDomains = Object.keys(DOMAIN_METADATA);
    for (const control of ALL_GOVERNANCE_CONTROLS) {
      expect(validDomains).toContain(control.domain);
    }
  });

  it('has correct ID prefixes per domain', () => {
    const prefixes: Record<string, string> = {
      'trust-hierarchy': 'TH-',
      'capability-boundaries': 'CB-',
      'injection-hardening': 'IH-',
      'data-handling': 'DH-',
      'hardcoded-behaviors': 'HB-',
      'agentic-safety': 'AS-',
      'honesty-transparency': 'HT-',
      'human-oversight': 'HO-',
    };

    for (const control of ALL_GOVERNANCE_CONTROLS) {
      const expected = prefixes[control.domain];
      expect(control.id).toMatch(new RegExp(`^${expected}\\d{3}$`));
    }
  });
});

describe('DOMAIN_METADATA', () => {
  it('defines all 8 domains', () => {
    expect(Object.keys(DOMAIN_METADATA)).toHaveLength(8);
  });

  it('has domain numbers 7 through 14', () => {
    const numbers = Object.values(DOMAIN_METADATA).map(m => m.number).sort((a, b) => a - b);
    expect(numbers).toEqual([7, 8, 9, 10, 11, 12, 13, 14]);
  });

  it('every domain has a non-empty name', () => {
    for (const meta of Object.values(DOMAIN_METADATA)) {
      expect(meta.name).toBeTruthy();
    }
  });
});

describe('Control distribution across domains', () => {
  const expectedCounts: Record<string, number> = {
    'trust-hierarchy': 8,
    'capability-boundaries': 10,
    'injection-hardening': 8,
    'data-handling': 8,
    'hardcoded-behaviors': 8,
    'agentic-safety': 10,
    'honesty-transparency': 8,
    'human-oversight': 8,
  };

  for (const [domain, count] of Object.entries(expectedCounts)) {
    it(`${domain} has ${count} controls`, () => {
      const controls = getControlsByDomain(domain as GovernanceDomain);
      expect(controls).toHaveLength(count);
    });
  }
});

describe('getControlById', () => {
  it('returns the correct control for a valid ID', () => {
    const control = getControlById('TH-001');
    expect(control).toBeDefined();
    expect(control!.id).toBe('TH-001');
    expect(control!.domain).toBe('trust-hierarchy');
  });

  it('returns undefined for an invalid ID', () => {
    expect(getControlById('INVALID-999')).toBeUndefined();
  });

  it('retrieves controls from every domain', () => {
    const sampleIds = ['TH-001', 'CB-001', 'IH-001', 'DH-001', 'HB-001', 'AS-001', 'HT-001', 'HO-001'];
    for (const id of sampleIds) {
      expect(getControlById(id)).toBeDefined();
    }
  });
});

describe('getControlsForTier', () => {
  it('basic tier gets some controls', () => {
    const controls = getControlsForTier('basic');
    expect(controls.length).toBeGreaterThan(0);
  });

  it('higher tiers include more or equal controls', () => {
    const tiers: AgentTier[] = ['basic', 'tool-using', 'agentic', 'multi-agent'];
    let prev = 0;
    for (const tier of tiers) {
      const count = getControlsForTier(tier).length;
      expect(count).toBeGreaterThanOrEqual(prev);
      prev = count;
    }
  });

  it('multi-agent tier includes all 68 controls', () => {
    const controls = getControlsForTier('multi-agent');
    expect(controls).toHaveLength(68);
  });
});

describe('getControlsBySeverity', () => {
  it('returns controls for each severity level', () => {
    const severities: GovernanceSeverity[] = ['critical', 'high', 'medium', 'low'];
    for (const sev of severities) {
      const controls = getControlsBySeverity(sev);
      expect(controls.length).toBeGreaterThan(0);
      for (const c of controls) {
        expect(c.severity).toBe(sev);
      }
    }
  });

  it('all severity groups sum to 68', () => {
    const total = (['critical', 'high', 'medium', 'low'] as GovernanceSeverity[])
      .reduce((sum, sev) => sum + getControlsBySeverity(sev).length, 0);
    expect(total).toBe(68);
  });
});
