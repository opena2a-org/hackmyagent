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

  // Round to 2 decimal places
  overall = Math.round(overall * 100) / 100;

  return {
    overall,
    factors,
    calculatedAt: new Date().toISOString(),
  };
}
