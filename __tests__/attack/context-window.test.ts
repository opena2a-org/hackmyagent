/**
 * Context Window Payload Tests
 */

import { describe, it, expect } from 'vitest';
import { CONTEXT_WINDOW_PAYLOADS } from '../../src/attack/payloads/context-window';
import { getPayloadsByCategory } from '../../src/attack/payloads';

describe('Context Window Payloads', () => {
  it('contains exactly 10 payloads', () => {
    expect(CONTEXT_WINDOW_PAYLOADS).toHaveLength(10);
  });

  it('all payloads have unique IDs', () => {
    const ids = CONTEXT_WINDOW_PAYLOADS.map(p => p.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it('all IDs follow CTX-XXX convention', () => {
    for (const p of CONTEXT_WINDOW_PAYLOADS) {
      expect(p.id).toMatch(/^CTX-\d{3}$/);
    }
  });

  it('all payloads have correct category', () => {
    for (const p of CONTEXT_WINDOW_PAYLOADS) {
      expect(p.category).toBe('context-window');
    }
  });

  it('all payloads have required fields', () => {
    for (const p of CONTEXT_WINDOW_PAYLOADS) {
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
    for (const p of CONTEXT_WINDOW_PAYLOADS) {
      for (const i of p.successIndicators) expect(i).toBeInstanceOf(RegExp);
      for (const i of p.blockedIndicators) expect(i).toBeInstanceOf(RegExp);
    }
  });

  it('has correct intensity distribution (2 passive, 5 active, 3 aggressive)', () => {
    expect(CONTEXT_WINDOW_PAYLOADS.filter(p => p.intensity === 'passive')).toHaveLength(2);
    expect(CONTEXT_WINDOW_PAYLOADS.filter(p => p.intensity === 'active')).toHaveLength(5);
    expect(CONTEXT_WINDOW_PAYLOADS.filter(p => p.intensity === 'aggressive')).toHaveLength(3);
  });

  it('getPayloadsByCategory returns correct count', () => {
    const payloads = getPayloadsByCategory('context-window');
    expect(payloads).toHaveLength(10);
    for (const p of payloads) expect(p.category).toBe('context-window');
  });

  it('IDs are sequential from CTX-001 to CTX-010', () => {
    for (let i = 0; i < 10; i++) {
      expect(CONTEXT_WINDOW_PAYLOADS[i].id).toBe(`CTX-${String(i + 1).padStart(3, '0')}`);
    }
  });

  it('all payloads have oasbControl set', () => {
    for (const p of CONTEXT_WINDOW_PAYLOADS) expect(p.oasbControl).toBeTruthy();
  });
});
