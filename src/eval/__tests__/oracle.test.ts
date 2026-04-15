import { describe, it, expect } from 'vitest';
import {
  derivePrediction,
  computeMetrics,
  GATE_RECALL,
  GATE_PRECISION,
  GATE_F1,
  type HmaFinding,
  type FixtureResult,
  type OracleSurface,
} from '../oracle';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFixture(
  expected: string,
  predicted: string,
  severity = 'medium',
  surface: OracleSurface = 'skill',
): FixtureResult {
  return {
    fixturePath: '/fake/path',
    surface,
    attackFamily: 'test',
    hardNegative: false,
    expectedLabel: expected as FixtureResult['expectedLabel'],
    expectedSeverity: severity,
    expectedChecks: [],
    predictedLabel: predicted as FixtureResult['predictedLabel'],
    predictedSeverity: severity,
    firedChecks: [],
    correct: expected === predicted,
    severityCorrect: true,
    missingExpectedChecks: [],
    scanOutput: [],
  };
}

// ── Gate constants ────────────────────────────────────────────────────────────

describe('Gate threshold constants', () => {
  it('exports GATE_RECALL = 0.85', () => {
    expect(GATE_RECALL).toBe(0.85);
  });

  it('exports GATE_PRECISION = 0.90', () => {
    expect(GATE_PRECISION).toBe(0.90);
  });

  it('exports GATE_F1 = 0.80', () => {
    expect(GATE_F1).toBe(0.80);
  });
});

// ── derivePrediction ──────────────────────────────────────────────────────────

describe('derivePrediction', () => {
  it('returns benign/none/empty for no findings', () => {
    const result = derivePrediction([]);
    expect(result.label).toBe('benign');
    expect(result.severity).toBe('none');
    expect(result.firedChecks).toEqual([]);
  });

  it('returns benign when all findings passed=true', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-001', severity: 'high', passed: true },
      { checkId: 'CHK-002', severity: 'critical', passed: true },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('benign');
    expect(result.firedChecks).toEqual([]);
  });

  it('maps attackClass "inject" to label "injection"', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-001', severity: 'high', attackClass: 'prompt_inject', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('injection');
    expect(result.severity).toBe('high');
  });

  it('maps attackClass "credential" to label "credential_abuse"', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-002', severity: 'critical', attackClass: 'credential_leak', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('credential_abuse');
    expect(result.severity).toBe('critical');
  });

  it('maps attackClass "exfil" to label "exfiltration"', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-003', severity: 'high', attackClass: 'data_exfiltrat', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('exfiltration');
  });

  it('falls back to category "soul" -> governance_gap when no attackClass', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-010', severity: 'medium', attackClass: null, category: 'soul', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('governance_gap');
  });

  it('falls back to category "mcp" -> scope_mismatch when no attackClass', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-011', severity: 'medium', attackClass: null, category: 'mcp', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.label).toBe('scope_mismatch');
  });

  it('picks highest-severity finding when multiple malicious findings exist', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-A', severity: 'low', attackClass: 'persist', passed: false },
      { checkId: 'CHK-B', severity: 'critical', attackClass: 'inject', passed: false },
      { checkId: 'CHK-C', severity: 'medium', attackClass: 'exfil', passed: false },
    ];
    const result = derivePrediction(findings);
    // critical > medium > low, so injection (from 'inject' at critical) wins
    expect(result.label).toBe('injection');
    expect(result.severity).toBe('critical');
  });

  it('firedChecks includes only failed findings with a checkId', () => {
    const findings: HmaFinding[] = [
      { checkId: 'CHK-PASS', severity: 'high', passed: true },
      { checkId: 'CHK-FAIL-1', severity: 'high', attackClass: 'inject', passed: false },
      { severity: 'medium', attackClass: 'exfil', passed: false },  // no checkId
      { checkId: 'CHK-FAIL-2', severity: 'low', attackClass: 'persist', passed: false },
    ];
    const result = derivePrediction(findings);
    expect(result.firedChecks).toContain('CHK-FAIL-1');
    expect(result.firedChecks).toContain('CHK-FAIL-2');
    expect(result.firedChecks).not.toContain('CHK-PASS');
    expect(result.firedChecks).toHaveLength(2);
  });
});

// ── computeMetrics ────────────────────────────────────────────────────────────

describe('computeMetrics', () => {
  it('all true positives: precision=1, recall=1, f1=1', () => {
    const fixtures = [
      makeFixture('injection', 'injection'),
      makeFixture('exfiltration', 'exfiltration'),
      makeFixture('credential_abuse', 'credential_abuse'),
    ];
    const m = computeMetrics(fixtures, 'all');
    expect(m.precision).toBe(1);
    expect(m.recall).toBe(1);
    expect(m.f1).toBe(1);
    expect(m.tp).toBe(3);
    expect(m.fp).toBe(0);
    expect(m.fn).toBe(0);
    expect(m.tn).toBe(0);
  });

  it('all benign correctly passed: tn=N, precision=0 (no positives), fpr=0', () => {
    const fixtures = [
      makeFixture('benign', 'benign'),
      makeFixture('benign', 'benign'),
    ];
    const m = computeMetrics(fixtures, 'all');
    expect(m.tn).toBe(2);
    expect(m.fp).toBe(0);
    expect(m.tp).toBe(0);
    expect(m.fn).toBe(0);
    expect(m.precision).toBe(0);  // tp+fp=0 → 0 (not NaN)
    expect(m.recall).toBe(0);     // tp+fn=0 → 0 (not NaN)
    expect(m.fpr).toBe(0);
    expect(Number.isNaN(m.precision)).toBe(false);
    expect(Number.isNaN(m.recall)).toBe(false);
  });

  it('all false positives: fp=N, precision=0, fpr=1', () => {
    const fixtures = [
      makeFixture('benign', 'injection'),
      makeFixture('benign', 'exfiltration'),
    ];
    const m = computeMetrics(fixtures, 'all');
    expect(m.fp).toBe(2);
    expect(m.tp).toBe(0);
    expect(m.tn).toBe(0);
    expect(m.precision).toBe(0);
    expect(m.fpr).toBe(1);
  });

  it('all false negatives: fn=N, recall=0; criticalMissed counts critical severity FNs', () => {
    const fixtures = [
      makeFixture('injection', 'benign', 'critical'),
      makeFixture('exfiltration', 'benign', 'high'),
      makeFixture('credential_abuse', 'benign', 'critical'),
    ];
    const m = computeMetrics(fixtures, 'all');
    expect(m.fn).toBe(3);
    expect(m.tp).toBe(0);
    expect(m.recall).toBe(0);
    expect(m.precision).toBe(0);
    expect(m.criticalMissed).toBe(2);  // only critical-severity FNs
  });

  it('zero-denominator guards: tp+fp=0 → precision=0; tp+fn=0 → recall=0 (not NaN)', () => {
    // Empty subset
    const m = computeMetrics([], 'all');
    expect(m.precision).toBe(0);
    expect(m.recall).toBe(0);
    expect(m.f1).toBe(0);
    expect(m.fpr).toBe(0);
    expect(Number.isNaN(m.precision)).toBe(false);
    expect(Number.isNaN(m.recall)).toBe(false);
    expect(Number.isNaN(m.f1)).toBe(false);
    expect(Number.isNaN(m.fpr)).toBe(false);
  });

  it('mixed TP/FP/FN/TN: verifies arithmetic', () => {
    // 3 TP, 1 FP, 1 FN, 2 TN
    const fixtures = [
      makeFixture('injection', 'injection'),       // TP
      makeFixture('exfiltration', 'exfiltration'), // TP
      makeFixture('credential_abuse', 'credential_abuse'), // TP
      makeFixture('benign', 'injection'),          // FP
      makeFixture('injection', 'benign'),          // FN (medium severity)
      makeFixture('benign', 'benign'),             // TN
      makeFixture('benign', 'benign'),             // TN
    ];
    const m = computeMetrics(fixtures, 'skill');
    expect(m.tp).toBe(3);
    expect(m.fp).toBe(1);
    expect(m.fn).toBe(1);
    expect(m.tn).toBe(2);
    // precision = 3/(3+1) = 0.75
    expect(m.precision).toBeCloseTo(0.75, 3);
    // recall = 3/(3+1) = 0.75
    expect(m.recall).toBeCloseTo(0.75, 3);
    // f1 = 2*0.75*0.75/(0.75+0.75) = 0.75
    expect(m.f1).toBeCloseTo(0.75, 3);
    // fpr = 1/(1+2) ≈ 0.333
    expect(m.fpr).toBeCloseTo(0.333, 2);
    expect(m.surface).toBe('skill');
    expect(m.total).toBe(7);
    expect(m.maliciousTotal).toBe(4);
    expect(m.benignTotal).toBe(3);
    expect(m.criticalMissed).toBe(0); // FN was medium severity
  });

  it('criticalMissed is 0 when all malicious are correctly detected', () => {
    const fixtures = [
      makeFixture('injection', 'injection', 'critical'),
      makeFixture('exfiltration', 'exfiltration', 'critical'),
    ];
    const m = computeMetrics(fixtures, 'all');
    expect(m.criticalMissed).toBe(0);
  });
});
