import { describe, it, expect } from 'vitest';
import { PERSISTENT_AGENT_PAYLOADS } from '../../src/attack/payloads/persistent-agent';
import { getPayloadsByCategory } from '../../src/attack/payloads';

describe('Persistent Agent Payloads', () => {
  it('contains exactly 10 payloads', () => {
    expect(PERSISTENT_AGENT_PAYLOADS).toHaveLength(10);
  });

  it('all payloads have unique IDs', () => {
    const ids = PERSISTENT_AGENT_PAYLOADS.map(p => p.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it('all IDs follow PERSIST-XXX convention', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) {
      expect(p.id).toMatch(/^PERSIST-\d{3}$/);
    }
  });

  it('all payloads have correct category', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) {
      expect(p.category).toBe('persistent-agent');
    }
  });

  it('all payloads have required fields', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) {
      expect(p.id).toBeTruthy();
      expect(p.name).toBeTruthy();
      expect(p.description).toBeTruthy();
      expect(p.intensity).toBeTruthy();
      expect(p.payload).toBeTruthy();
      expect(p.severity).toBeTruthy();
      expect(p.remediation).toBeTruthy();
      expect(Array.isArray(p.successIndicators)).toBe(true);
      expect(Array.isArray(p.blockedIndicators)).toBe(true);
      expect(p.successIndicators.length).toBeGreaterThan(0);
      expect(p.blockedIndicators.length).toBeGreaterThan(0);
    }
  });

  it('all regex patterns compile', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) {
      for (const i of p.successIndicators) expect(i).toBeInstanceOf(RegExp);
      for (const i of p.blockedIndicators) expect(i).toBeInstanceOf(RegExp);
    }
  });

  it('has correct intensity distribution (2 passive, 4 active, 4 aggressive)', () => {
    expect(PERSISTENT_AGENT_PAYLOADS.filter(p => p.intensity === 'passive')).toHaveLength(2);
    expect(PERSISTENT_AGENT_PAYLOADS.filter(p => p.intensity === 'active')).toHaveLength(4);
    expect(PERSISTENT_AGENT_PAYLOADS.filter(p => p.intensity === 'aggressive')).toHaveLength(4);
  });

  it('getPayloadsByCategory returns correct count', () => {
    const payloads = getPayloadsByCategory('persistent-agent');
    expect(payloads).toHaveLength(10);
    for (const p of payloads) expect(p.category).toBe('persistent-agent');
  });

  it('IDs are sequential from PERSIST-001 to PERSIST-010', () => {
    for (let i = 0; i < 10; i++) {
      expect(PERSISTENT_AGENT_PAYLOADS[i].id)
        .toBe(`PERSIST-${String(i + 1).padStart(3, '0')}`);
    }
  });

  it('all payloads have oasbControl set', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) expect(p.oasbControl).toBeTruthy();
  });

  it('all payloads have CWE reference', () => {
    for (const p of PERSISTENT_AGENT_PAYLOADS) expect(p.cwe).toBeTruthy();
  });
});
