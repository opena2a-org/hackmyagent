/**
 * Attack Module Tests
 */

import { describe, it, expect } from 'vitest';
import { AttackScanner } from './scanner';
import {
  ALL_PAYLOADS,
  PAYLOAD_STATS,
  getPayloads,
  getPayloadById,
  getPayloadsByCategory,
  getPayloadsByIntensity,
  PROMPT_INJECTION_PAYLOADS,
  JAILBREAK_PAYLOADS,
  DATA_EXFILTRATION_PAYLOADS,
  CAPABILITY_ABUSE_PAYLOADS,
  CONTEXT_MANIPULATION_PAYLOADS,
} from './payloads';
import { ATTACK_CATEGORIES, AttackCategory, AttackIntensity, AttackPayload } from './types';

describe('Attack Payloads', () => {
  describe('payload structure', () => {
    it('all payloads have required fields', () => {
      for (const payload of ALL_PAYLOADS) {
        expect(payload.id).toBeTruthy();
        expect(payload.category).toBeTruthy();
        expect(payload.name).toBeTruthy();
        expect(payload.description).toBeTruthy();
        expect(payload.intensity).toBeTruthy();
        expect(payload.payload).toBeTruthy();
        expect(payload.severity).toBeTruthy();
        expect(payload.remediation).toBeTruthy();
        expect(Array.isArray(payload.successIndicators)).toBe(true);
        expect(Array.isArray(payload.blockedIndicators)).toBe(true);
      }
    });

    it('all payloads have unique IDs', () => {
      const ids = ALL_PAYLOADS.map(p => p.id);
      const uniqueIds = new Set(ids);
      expect(ids.length).toBe(uniqueIds.size);
    });

    it('payload IDs follow naming convention', () => {
      const prefixes: Record<AttackCategory, string> = {
        'prompt-injection': 'PI',
        'jailbreak': 'JB',
        'data-exfiltration': 'DE',
        'capability-abuse': 'CA',
        'context-manipulation': 'CM',
      };

      for (const payload of ALL_PAYLOADS) {
        const expectedPrefix = prefixes[payload.category];
        expect(payload.id.startsWith(expectedPrefix)).toBe(true);
        expect(payload.id).toMatch(/^[A-Z]{2}-\d{3}$/);
      }
    });

    it('all indicators are valid RegExp', () => {
      for (const payload of ALL_PAYLOADS) {
        for (const indicator of payload.successIndicators) {
          expect(indicator).toBeInstanceOf(RegExp);
        }
        for (const indicator of payload.blockedIndicators) {
          expect(indicator).toBeInstanceOf(RegExp);
        }
      }
    });
  });

  describe('PAYLOAD_STATS', () => {
    it('reports correct total count', () => {
      expect(PAYLOAD_STATS.total).toBe(ALL_PAYLOADS.length);
    });

    it('reports correct category counts', () => {
      expect(PAYLOAD_STATS.byCategory['prompt-injection']).toBe(PROMPT_INJECTION_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['jailbreak']).toBe(JAILBREAK_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['data-exfiltration']).toBe(DATA_EXFILTRATION_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['capability-abuse']).toBe(CAPABILITY_ABUSE_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['context-manipulation']).toBe(CONTEXT_MANIPULATION_PAYLOADS.length);
    });

    it('category counts sum to total', () => {
      const sum = Object.values(PAYLOAD_STATS.byCategory).reduce((a, b) => a + b, 0);
      expect(sum).toBe(PAYLOAD_STATS.total);
    });

    it('intensity counts sum to total', () => {
      const sum = Object.values(PAYLOAD_STATS.byIntensity).reduce((a, b) => a + b, 0);
      expect(sum).toBe(PAYLOAD_STATS.total);
    });
  });

  describe('getPayloadsByCategory', () => {
    it('returns only payloads of specified category', () => {
      const categories: AttackCategory[] = [
        'prompt-injection',
        'jailbreak',
        'data-exfiltration',
        'capability-abuse',
        'context-manipulation',
      ];

      for (const category of categories) {
        const payloads = getPayloadsByCategory(category);
        expect(payloads.length).toBeGreaterThan(0);
        for (const payload of payloads) {
          expect(payload.category).toBe(category);
        }
      }
    });
  });

  describe('getPayloadsByIntensity', () => {
    it('passive returns only passive payloads', () => {
      const payloads = getPayloadsByIntensity('passive');
      for (const payload of payloads) {
        expect(payload.intensity).toBe('passive');
      }
    });

    it('active returns passive and active payloads', () => {
      const payloads = getPayloadsByIntensity('active');
      const intensities = new Set(payloads.map(p => p.intensity));
      expect(intensities.has('aggressive')).toBe(false);
    });

    it('aggressive returns all payloads', () => {
      const payloads = getPayloadsByIntensity('aggressive');
      expect(payloads.length).toBe(ALL_PAYLOADS.length);
    });
  });

  describe('getPayloads', () => {
    it('returns all payloads when no filters', () => {
      const payloads = getPayloads(undefined, 'aggressive');
      expect(payloads.length).toBe(ALL_PAYLOADS.length);
    });

    it('filters by category', () => {
      const payloads = getPayloads(['prompt-injection'], 'aggressive');
      for (const payload of payloads) {
        expect(payload.category).toBe('prompt-injection');
      }
    });

    it('filters by multiple categories', () => {
      const payloads = getPayloads(['prompt-injection', 'jailbreak'], 'aggressive');
      for (const payload of payloads) {
        expect(['prompt-injection', 'jailbreak']).toContain(payload.category);
      }
    });

    it('combines category and intensity filters', () => {
      const payloads = getPayloads(['prompt-injection'], 'passive');
      for (const payload of payloads) {
        expect(payload.category).toBe('prompt-injection');
        expect(payload.intensity).toBe('passive');
      }
    });
  });

  describe('getPayloadById', () => {
    it('returns payload for valid ID', () => {
      const payload = getPayloadById('PI-001');
      expect(payload).toBeDefined();
      expect(payload?.id).toBe('PI-001');
    });

    it('returns undefined for invalid ID', () => {
      const payload = getPayloadById('INVALID-999');
      expect(payload).toBeUndefined();
    });
  });
});

describe('ATTACK_CATEGORIES', () => {
  it('has all categories defined', () => {
    const categories: AttackCategory[] = [
      'prompt-injection',
      'jailbreak',
      'data-exfiltration',
      'capability-abuse',
      'context-manipulation',
    ];

    for (const category of categories) {
      expect(ATTACK_CATEGORIES[category]).toBeDefined();
      expect(ATTACK_CATEGORIES[category].name).toBeTruthy();
      expect(ATTACK_CATEGORIES[category].description).toBeTruthy();
      expect(Array.isArray(ATTACK_CATEGORIES[category].oasbControls)).toBe(true);
    }
  });
});

describe('AttackScanner', () => {
  describe('constructor', () => {
    it('creates scanner with default options', () => {
      const scanner = new AttackScanner();
      expect(scanner).toBeInstanceOf(AttackScanner);
    });

    it('creates scanner with custom options', () => {
      const scanner = new AttackScanner({
        intensity: 'aggressive',
        timeout: 60000,
        delay: 500,
      });
      expect(scanner).toBeInstanceOf(AttackScanner);
    });
  });

  describe('scan (local mode)', () => {
    it('runs scan in local simulation mode', async () => {
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { categories: ['prompt-injection'], intensity: 'passive', delay: 0 }
      );

      expect(report.target).toBe('local');
      expect(report.targetType).toBe('local');
      expect(report.intensity).toBe('passive');
      expect(report.categories).toContain('prompt-injection');
      expect(report.summary.total).toBeGreaterThan(0);
      expect(report.results.length).toBe(report.summary.total);
      expect(report.riskScore).toBeGreaterThanOrEqual(0);
      expect(report.riskScore).toBeLessThanOrEqual(100);
    });

    it('respects stopOnSuccess option', async () => {
      // Create a scanner that will stop on first success
      // In local mode, most will be inconclusive, but we test the flow
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { intensity: 'passive', stopOnSuccess: true, delay: 0 }
      );

      // Should have at least one result
      expect(report.results.length).toBeGreaterThanOrEqual(1);
    });

    it('returns correct summary structure', async () => {
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { categories: ['jailbreak'], intensity: 'passive', delay: 0 }
      );

      expect(report.summary).toHaveProperty('total');
      expect(report.summary).toHaveProperty('successful');
      expect(report.summary).toHaveProperty('blocked');
      expect(report.summary).toHaveProperty('inconclusive');
      expect(report.summary).toHaveProperty('bySeverity');
      expect(report.summary).toHaveProperty('byCategory');

      // Check bySeverity structure
      expect(report.summary.bySeverity).toHaveProperty('critical');
      expect(report.summary.bySeverity).toHaveProperty('high');
      expect(report.summary.bySeverity).toHaveProperty('medium');
      expect(report.summary.bySeverity).toHaveProperty('low');
      expect(report.summary.bySeverity).toHaveProperty('info');

      // Check byCategory structure
      expect(report.summary.byCategory).toHaveProperty('jailbreak');
      expect(report.summary.byCategory['jailbreak']).toHaveProperty('total');
      expect(report.summary.byCategory['jailbreak']).toHaveProperty('successful');
    });

    it('calculates risk rating correctly', async () => {
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { categories: ['prompt-injection'], intensity: 'passive', delay: 0 }
      );

      // Risk rating should be one of the valid values
      expect(['critical', 'high', 'medium', 'low', 'secure']).toContain(report.riskRating);

      // Score and rating should be consistent
      if (report.riskScore >= 70) {
        expect(report.riskRating).toBe('critical');
      } else if (report.riskScore >= 50) {
        expect(report.riskRating).toBe('high');
      } else if (report.riskScore >= 25) {
        expect(report.riskRating).toBe('medium');
      } else if (report.riskScore > 0) {
        expect(report.riskRating).toBe('low');
      } else {
        expect(report.riskRating).toBe('secure');
      }
    });

    it('includes duration in report', async () => {
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { categories: ['prompt-injection'], intensity: 'passive', delay: 0 }
      );

      expect(report.duration).toBeGreaterThanOrEqual(0);
      expect(report.startTime).toBeInstanceOf(Date);
      expect(report.endTime).toBeInstanceOf(Date);
    });

    it('runs specific payloads by ID', async () => {
      const scanner = new AttackScanner({ delay: 0 });
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { payloadIds: ['PI-001', 'JB-001'], delay: 0 }
      );

      expect(report.results.length).toBe(2);
      const ids = report.results.map(r => r.payload.id);
      expect(ids).toContain('PI-001');
      expect(ids).toContain('JB-001');
    });
  });

  describe('response analysis', () => {
    it('detects blocked responses', async () => {
      const scanner = new AttackScanner({ delay: 0 });

      // The local simulation doesn't trigger blocked patterns,
      // but we verify the structure is in place
      const report = await scanner.scan(
        { url: '', type: 'local' },
        { categories: ['prompt-injection'], intensity: 'passive', delay: 0 }
      );

      // Each result should have the blocked field
      for (const result of report.results) {
        expect(typeof result.blocked).toBe('boolean');
        expect(typeof result.success).toBe('boolean');
        expect(typeof result.confidence).toBe('number');
        expect(result.confidence).toBeGreaterThanOrEqual(0);
        expect(result.confidence).toBeLessThanOrEqual(1);
      }
    });
  });
});

describe('Attack Result Structure', () => {
  it('results have all required fields', async () => {
    const scanner = new AttackScanner({ delay: 0 });
    const report = await scanner.scan(
      { url: '', type: 'local' },
      { categories: ['prompt-injection'], intensity: 'passive', delay: 0 }
    );

    for (const result of report.results) {
      expect(result.payload).toBeDefined();
      expect(result.target).toBeDefined();
      expect(typeof result.success).toBe('boolean');
      expect(typeof result.blocked).toBe('boolean');
      expect(typeof result.confidence).toBe('number');
      expect(result.evidence).toBeDefined();
      expect(typeof result.duration).toBe('number');
      expect(result.timestamp).toBeInstanceOf(Date);
    }
  });
});
