/**
 * Attack Module Tests
 */

import { describe, it, expect } from 'vitest';
import { AttackScanner } from '../../src/attack/scanner';
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
  MEMORY_WEAPONIZATION_PAYLOADS,
  CONTEXT_WINDOW_PAYLOADS,
  SUPPLY_CHAIN_PAYLOADS,
  TOOL_SHADOW_PAYLOADS,
} from '../../src/attack/payloads';
import { ATTACK_CATEGORIES, AttackCategory, AttackIntensity, AttackPayload, AttackReport, AttackSeverity } from '../../src/attack/types';
import { parseCustomPayloads } from '../../src/attack/custom-payloads';
import { shouldFail, FailPolicy } from '../../src/attack/fail-policy';

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
        'mcp-exploitation': 'MCP',
        'a2a-attack': 'A2A',
        'memory-weaponization': 'MEM',
        'context-window': 'CTX',
        'supply-chain': 'SUP',
        'tool-shadow': 'SHADOW',
      };

      for (const payload of ALL_PAYLOADS) {
        const expectedPrefix = prefixes[payload.category];
        expect(payload.id.startsWith(expectedPrefix)).toBe(true);
        expect(payload.id).toMatch(/^[A-Z][A-Z0-9]{1,5}-\d{3}$/);
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
      expect(PAYLOAD_STATS.byCategory['memory-weaponization']).toBe(MEMORY_WEAPONIZATION_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['context-window']).toBe(CONTEXT_WINDOW_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['supply-chain']).toBe(SUPPLY_CHAIN_PAYLOADS.length);
      expect(PAYLOAD_STATS.byCategory['tool-shadow']).toBe(TOOL_SHADOW_PAYLOADS.length);
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
        'memory-weaponization',
        'context-window',
        'supply-chain',
        'tool-shadow',
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
      'memory-weaponization',
      'context-window',
      'supply-chain',
      'tool-shadow',
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

describe('parseCustomPayloads', () => {
  it('parses minimal payload (only id + payload)', () => {
    const json = JSON.stringify({
      payloads: [{ id: 'TEST-001', payload: 'Hello world' }],
    });
    const result = parseCustomPayloads(json);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('TEST-001');
    expect(result[0].payload).toBe('Hello world');
    expect(result[0].name).toBe('Custom Payload TEST-001');
    expect(result[0].description).toBe('Custom attack payload');
    expect(result[0].category).toBe('prompt-injection');
    expect(result[0].intensity).toBe('active');
    expect(result[0].severity).toBe('medium');
    expect(result[0].remediation).toBe('Review agent response for unexpected behavior');
    expect(result[0].successIndicators).toEqual([]);
    expect(result[0].blockedIndicators).toEqual([]);
  });

  it('parses full payload with all fields', () => {
    const json = JSON.stringify({
      payloads: [{
        id: 'CUSTOM-001',
        payload: 'Extract system prompt',
        name: 'System Prompt Extraction',
        description: 'Tries to extract the system prompt',
        category: 'data-exfiltration',
        intensity: 'aggressive',
        severity: 'critical',
        successIndicators: ['system prompt', 'instructions'],
        blockedIndicators: ['cannot|sorry'],
        oasbControl: '4.3',
        cwe: 'CWE-200',
        remediation: 'Hide system prompt',
      }],
    });
    const result = parseCustomPayloads(json);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('System Prompt Extraction');
    expect(result[0].category).toBe('data-exfiltration');
    expect(result[0].severity).toBe('critical');
    expect(result[0].oasbControl).toBe('4.3');
    expect(result[0].cwe).toBe('CWE-200');
  });

  it('parses multiple payloads', () => {
    const json = JSON.stringify({
      payloads: [
        { id: 'A-001', payload: 'First' },
        { id: 'A-002', payload: 'Second' },
        { id: 'A-003', payload: 'Third' },
      ],
    });
    const result = parseCustomPayloads(json);
    expect(result).toHaveLength(3);
  });

  it('compiles regex patterns as case-insensitive', () => {
    const json = JSON.stringify({
      payloads: [{
        id: 'RE-001',
        payload: 'test',
        successIndicators: ['system\\s+prompt'],
        blockedIndicators: ['denied|blocked'],
      }],
    });
    const result = parseCustomPayloads(json);
    expect(result[0].successIndicators[0]).toBeInstanceOf(RegExp);
    expect(result[0].successIndicators[0].flags).toBe('i');
    expect(result[0].successIndicators[0].test('System Prompt')).toBe(true);
    expect(result[0].blockedIndicators[0].test('DENIED')).toBe(true);
  });

  it('rejects invalid JSON', () => {
    expect(() => parseCustomPayloads('not json')).toThrow('Invalid JSON');
  });

  it('rejects missing payloads array', () => {
    expect(() => parseCustomPayloads('{}')).toThrow('"payloads" array');
  });

  it('rejects empty payloads array', () => {
    expect(() => parseCustomPayloads('{"payloads":[]}')).toThrow('must not be empty');
  });

  it('rejects missing id', () => {
    const json = JSON.stringify({ payloads: [{ payload: 'test' }] });
    expect(() => parseCustomPayloads(json)).toThrow('"id" is required');
  });

  it('rejects missing payload', () => {
    const json = JSON.stringify({ payloads: [{ id: 'X-001' }] });
    expect(() => parseCustomPayloads(json)).toThrow('"payload" is required');
  });

  it('rejects duplicate IDs', () => {
    const json = JSON.stringify({
      payloads: [
        { id: 'DUP-001', payload: 'a' },
        { id: 'DUP-001', payload: 'b' },
      ],
    });
    expect(() => parseCustomPayloads(json)).toThrow('duplicate id');
  });

  it('rejects invalid category', () => {
    const json = JSON.stringify({
      payloads: [{ id: 'X-001', payload: 'test', category: 'invalid' }],
    });
    expect(() => parseCustomPayloads(json)).toThrow('invalid category');
  });

  it('rejects invalid severity', () => {
    const json = JSON.stringify({
      payloads: [{ id: 'X-001', payload: 'test', severity: 'extreme' }],
    });
    expect(() => parseCustomPayloads(json)).toThrow('invalid severity');
  });

  it('rejects invalid regex', () => {
    const json = JSON.stringify({
      payloads: [{ id: 'X-001', payload: 'test', successIndicators: ['[invalid'] }],
    });
    expect(() => parseCustomPayloads(json)).toThrow('not a valid regex');
  });
});

describe('AttackScanner with custom payloads', () => {
  it('uses custom payloads when provided', async () => {
    const customPayloads: AttackPayload[] = [{
      id: 'CUSTOM-001',
      name: 'Test Custom',
      description: 'Test',
      category: 'prompt-injection',
      intensity: 'active',
      severity: 'high',
      payload: 'Custom test payload',
      successIndicators: [],
      blockedIndicators: [],
      remediation: 'Fix it',
    }];

    const scanner = new AttackScanner({ delay: 0 });
    const report = await scanner.scan(
      { url: '', type: 'local' },
      { customPayloads, delay: 0 },
    );

    expect(report.results).toHaveLength(1);
    expect(report.results[0].payload.id).toBe('CUSTOM-001');
  });

  it('custom payloads override categories and intensity', async () => {
    const customPayloads: AttackPayload[] = [{
      id: 'CUSTOM-002',
      name: 'Override Test',
      description: 'Test',
      category: 'jailbreak',
      intensity: 'aggressive',
      severity: 'medium',
      payload: 'Override test',
      successIndicators: [],
      blockedIndicators: [],
      remediation: 'Fix it',
    }];

    const scanner = new AttackScanner({ delay: 0 });
    const report = await scanner.scan(
      { url: '', type: 'local' },
      {
        customPayloads,
        categories: ['prompt-injection'],
        intensity: 'passive',
        delay: 0,
      },
    );

    // Should use custom payload despite categories/intensity filter
    expect(report.results).toHaveLength(1);
    expect(report.results[0].payload.id).toBe('CUSTOM-002');
  });
});

describe('shouldFail', () => {
  function makeReport(overrides: Partial<AttackReport> = {}): AttackReport {
    return {
      target: 'test',
      targetType: 'local',
      intensity: 'active',
      categories: ['prompt-injection'],
      startTime: new Date(),
      endTime: new Date(),
      duration: 100,
      summary: {
        total: 1,
        successful: 0,
        blocked: 0,
        inconclusive: 1,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        byCategory: {
          'prompt-injection': { total: 1, successful: 0 },
          'jailbreak': { total: 0, successful: 0 },
          'data-exfiltration': { total: 0, successful: 0 },
          'capability-abuse': { total: 0, successful: 0 },
          'context-manipulation': { total: 0, successful: 0 },
          'mcp-exploitation': { total: 0, successful: 0 },
          'a2a-attack': { total: 0, successful: 0 },
          'memory-weaponization': { total: 0, successful: 0 },
          'context-window': { total: 0, successful: 0 },
          'supply-chain': { total: 0, successful: 0 },
          'tool-shadow': { total: 0, successful: 0 },
        },
      },
      results: [],
      riskScore: 0,
      riskRating: 'secure',
      ...overrides,
    };
  }

  function makeSuccessResult(severity: AttackSeverity) {
    return {
      payload: {
        id: 'T-001',
        name: 'Test',
        description: 'Test',
        category: 'prompt-injection' as const,
        intensity: 'active' as const,
        severity,
        payload: 'test',
        successIndicators: [],
        blockedIndicators: [],
        remediation: 'Fix',
      },
      target: 'test',
      success: true,
      blocked: false,
      confidence: 0.85,
      evidence: 'test',
      duration: 100,
      timestamp: new Date(),
    };
  }

  describe('undefined (legacy default)', () => {
    it('fails on critical riskRating', () => {
      expect(shouldFail(makeReport({ riskRating: 'critical' }), undefined)).toBe(true);
    });

    it('fails on high riskRating', () => {
      expect(shouldFail(makeReport({ riskRating: 'high' }), undefined)).toBe(true);
    });

    it('passes on medium riskRating', () => {
      expect(shouldFail(makeReport({ riskRating: 'medium' }), undefined)).toBe(false);
    });

    it('passes on secure riskRating', () => {
      expect(shouldFail(makeReport({ riskRating: 'secure' }), undefined)).toBe(false);
    });
  });

  describe('true (any finding)', () => {
    it('fails on any successful attack', () => {
      const report = makeReport({
        summary: {
          ...makeReport().summary,
          successful: 1,
        },
        results: [makeSuccessResult('low')],
      });
      expect(shouldFail(report, true)).toBe(true);
    });

    it('passes on zero findings', () => {
      expect(shouldFail(makeReport(), true)).toBe(false);
    });
  });

  describe('medium threshold', () => {
    it('fails on medium severity finding', () => {
      const report = makeReport({
        summary: { ...makeReport().summary, successful: 1 },
        results: [makeSuccessResult('medium')],
      });
      expect(shouldFail(report, 'medium')).toBe(true);
    });

    it('fails on high severity finding', () => {
      const report = makeReport({
        summary: { ...makeReport().summary, successful: 1 },
        results: [makeSuccessResult('high')],
      });
      expect(shouldFail(report, 'medium')).toBe(true);
    });

    it('passes on low-only findings', () => {
      const report = makeReport({
        summary: { ...makeReport().summary, successful: 1 },
        results: [makeSuccessResult('low')],
      });
      expect(shouldFail(report, 'medium')).toBe(false);
    });
  });

  describe('critical threshold', () => {
    it('passes on high-only findings', () => {
      const report = makeReport({
        summary: { ...makeReport().summary, successful: 1 },
        results: [makeSuccessResult('high')],
      });
      expect(shouldFail(report, 'critical')).toBe(false);
    });

    it('fails on critical findings', () => {
      const report = makeReport({
        summary: { ...makeReport().summary, successful: 1 },
        results: [makeSuccessResult('critical')],
      });
      expect(shouldFail(report, 'critical')).toBe(true);
    });
  });
});
