/**
 * Fail Policy
 * CI/CD gate logic for --fail-on-vulnerable
 */

import { AttackReport, AttackSeverity } from './types';
import { EXIT_PASS, EXIT_FAIL, EXIT_UNMEASURED } from '../check/verdict';

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
 * The exit code for an attack run, from the one derivation every command
 * shares.
 *
 * #406 — every arm of `shouldFail` reads `successful`, and zero successful
 * attacks against a target that was never reached returned `false`, so
 * `attack <unreachable> --fail-on-vulnerable` exited 0. No policy could
 * express "I could not tell", because the function's return type was boolean:
 * pass or fail, with no third state. It returns the exit code now, so an
 * unmeasured run reports 2 under every policy including the strictest.
 */
export function attackExitCode(report: AttackReport, policy: FailPolicy): 0 | 1 | 2 {
  if (!report.verdict.measured) return EXIT_UNMEASURED;
  return shouldFail(report, policy) ? EXIT_FAIL : EXIT_PASS;
}

/**
 * Determine if the process should exit with failure based on attack results.
 *
 * - undefined: legacy behavior — fail on critical/high riskRating
 * - true / 'low': fail if any successful attack
 * - severity: fail if any successful attack has severity >= threshold
 *
 * Only meaningful for a measured report; callers should use `attackExitCode`,
 * which handles the unmeasured case that this cannot express.
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
