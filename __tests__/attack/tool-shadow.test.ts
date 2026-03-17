/**
 * Tool Shadow Payload Tests
 */

import { describe, it, expect } from 'vitest';
import { TOOL_SHADOW_PAYLOADS } from '../../src/attack/payloads/tool-shadow';
import { getPayloadsByCategory } from '../../src/attack/payloads';

describe('Tool Shadow Payloads', () => {
  it('contains exactly 10 payloads', () => {
    expect(TOOL_SHADOW_PAYLOADS).toHaveLength(10);
  });

  it('all payloads have unique IDs', () => {
    const ids = TOOL_SHADOW_PAYLOADS.map(p => p.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it('all IDs follow SHADOW-XXX convention', () => {
    for (const p of TOOL_SHADOW_PAYLOADS) {
      expect(p.id).toMatch(/^SHADOW-\d{3}$/);
    }
  });

  it('all payloads have correct category', () => {
    for (const p of TOOL_SHADOW_PAYLOADS) {
      expect(p.category).toBe('tool-shadow');
    }
  });

  it('all payloads have required fields', () => {
    for (const p of TOOL_SHADOW_PAYLOADS) {
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
    for (const p of TOOL_SHADOW_PAYLOADS) {
      for (const i of p.successIndicators) expect(i).toBeInstanceOf(RegExp);
      for (const i of p.blockedIndicators) expect(i).toBeInstanceOf(RegExp);
    }
  });

  it('has correct intensity distribution (2 passive, 5 active, 3 aggressive)', () => {
    expect(TOOL_SHADOW_PAYLOADS.filter(p => p.intensity === 'passive')).toHaveLength(2);
    expect(TOOL_SHADOW_PAYLOADS.filter(p => p.intensity === 'active')).toHaveLength(5);
    expect(TOOL_SHADOW_PAYLOADS.filter(p => p.intensity === 'aggressive')).toHaveLength(3);
  });

  it('getPayloadsByCategory returns correct count', () => {
    const payloads = getPayloadsByCategory('tool-shadow');
    expect(payloads).toHaveLength(10);
    for (const p of payloads) expect(p.category).toBe('tool-shadow');
  });

  it('IDs are sequential from SHADOW-001 to SHADOW-010', () => {
    for (let i = 0; i < 10; i++) {
      expect(TOOL_SHADOW_PAYLOADS[i].id).toBe(`SHADOW-${String(i + 1).padStart(3, '0')}`);
    }
  });

  it('all payloads have oasbControl set', () => {
    for (const p of TOOL_SHADOW_PAYLOADS) expect(p.oasbControl).toBeTruthy();
  });
});
