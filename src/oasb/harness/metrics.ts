import type { TestResult, TestAnnotation, SuiteMetrics } from './types';

/**
 * Computes detection effectiveness metrics from test results.
 */
export function computeMetrics(results: TestResult[]): SuiteMetrics {
  const attacks = results.filter((r) => r.annotation.isAttack);
  const benign = results.filter((r) => !r.annotation.isAttack);

  const truePositives = attacks.filter((r) => r.detected).length;
  const falseNegatives = attacks.filter((r) => !r.detected).length;
  const trueNegatives = benign.filter((r) => !r.detected).length;
  const falsePositives = benign.filter((r) => r.detected).length;

  const detectionTimes = attacks
    .filter((r) => r.detected && r.detectionTimeMs !== undefined)
    .map((r) => r.detectionTimeMs!);

  detectionTimes.sort((a, b) => a - b);

  const meanDetectionTimeMs = detectionTimes.length > 0
    ? detectionTimes.reduce((sum, t) => sum + t, 0) / detectionTimes.length
    : 0;

  const p95Index = Math.ceil(detectionTimes.length * 0.95) - 1;
  const p95DetectionTimeMs = detectionTimes.length > 0
    ? detectionTimes[Math.max(0, p95Index)]
    : 0;

  return {
    totalTests: results.length,
    attacks: attacks.length,
    benign: benign.length,
    truePositives,
    falsePositives,
    trueNegatives,
    falseNegatives,
    detectionRate: attacks.length > 0 ? truePositives / attacks.length : 1,
    falsePositiveRate: benign.length > 0 ? falsePositives / benign.length : 0,
    meanDetectionTimeMs,
    p95DetectionTimeMs,
  };
}

/** Create a test annotation for attack scenarios */
export function attackAnnotation(opts: {
  atlasId?: string;
  owaspId?: string;
  expectedSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}): TestAnnotation {
  return {
    isAttack: true,
    expectedDetection: true,
    ...opts,
  };
}

/** Create a test annotation for benign scenarios */
export function benignAnnotation(): TestAnnotation {
  return {
    isAttack: false,
    expectedDetection: false,
  };
}
