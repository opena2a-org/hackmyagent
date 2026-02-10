import type { TrustScore, TrustFactors, TrustHints } from './types';
import { hasAuditLog } from './audit';
import { hasPolicy } from './policy';

/** Weight for each trust factor (must sum to 1.0) */
const WEIGHTS: Record<keyof TrustFactors, number> = {
  identity: 0.20,
  capabilities: 0.15,
  auditLog: 0.10,
  secretsManaged: 0.15,
  configSigned: 0.10,
  skillsVerified: 0.10,
  networkControlled: 0.10,
  heartbeatMonitored: 0.10,
};

/**
 * Extended plugin signals that boost the overall score.
 * Each active signal provides a small bonus (up to 0.05 total).
 * This rewards comprehensive security posture without changing the base weights.
 */
const EXTENDED_SIGNALS: Array<keyof TrustHints> = [
  'sessionsProtected',
  'promptsGuarded',
  'daemonHardened',
  'dlpEnabled',
  'runtimeProtected',
];
const MAX_EXTENDED_BONUS = 0.05;

/** Calculate trust score based on current state and plugin hints */
export function calculateTrust(
  dataDir: string,
  hasIdentity: boolean,
  hints?: TrustHints
): TrustScore {
  const factors: TrustFactors = {
    identity: hasIdentity ? 1.0 : 0.0,
    capabilities: hasPolicy(dataDir) ? 1.0 : 0.0,
    auditLog: hasAuditLog(dataDir) ? 1.0 : 0.0,
    secretsManaged: hints?.secretsManaged ? 1.0 : 0.0,
    configSigned: hints?.configSigned ? 1.0 : 0.0,
    skillsVerified: hints?.skillsVerified ? 1.0 : 0.0,
    networkControlled: hints?.networkControlled ? 1.0 : 0.0,
    heartbeatMonitored: hints?.heartbeatMonitored ? 1.0 : 0.0,
  };

  let overall = 0;
  for (const [factor, weight] of Object.entries(WEIGHTS)) {
    overall += factors[factor as keyof TrustFactors] * weight;
  }

  // Extended plugin bonus: each active signal adds a proportional share of the max bonus
  if (hints) {
    const activeExtended = EXTENDED_SIGNALS.filter((s) => hints[s]).length;
    if (activeExtended > 0) {
      const bonus = (activeExtended / EXTENDED_SIGNALS.length) * MAX_EXTENDED_BONUS;
      overall += bonus;
    }
  }

  // Cap at 1.0 and round to 2 decimal places
  overall = Math.round(Math.min(overall, 1.0) * 100) / 100;

  return {
    overall,
    factors,
    calculatedAt: new Date().toISOString(),
  };
}
