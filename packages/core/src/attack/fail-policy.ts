/**
 * Fail Policy
 * CI/CD gate logic for --fail-on-vulnerable
 */

import { AttackReport, AttackSeverity } from './types';

/** Policy: undefined = legacy, true = any finding, severity string = threshold */
export type FailPolicy = undefined | true | AttackSeverity;

const SEVERITY_ORDER: Record<AttackSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Determine if the process should exit with failure based on attack results.
 *
 * - undefined: legacy behavior — fail on critical/high riskRating
 * - true / 'low': fail if any successful attack
 * - severity: fail if any successful attack has severity >= threshold
 */
export function shouldFail(report: AttackReport, policy: FailPolicy): boolean {
  if (policy === undefined) {
    // Legacy default
    return report.riskRating === 'critical' || report.riskRating === 'high';
  }

  if (report.summary.successful === 0) {
    return false;
  }

  if (policy === true || policy === 'low') {
    return true;
  }

  const threshold = SEVERITY_ORDER[policy];
  return report.results.some(
    r => r.success && SEVERITY_ORDER[r.payload.severity] >= threshold,
  );
}
