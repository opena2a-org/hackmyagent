/**
 * Skill checker
 * Main entry point for checking a skill's safety
 */

import { parseSkillIdentifier } from './skill-identifier';
import { analyzePermissions } from './permission-analyzer';
import { verifyPublisher, type VerifyOptions } from './publisher-verifier';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface PublisherInfo {
  name: string;
  verified: boolean;
  verificationMethod?: 'dns' | 'github' | 'none';
  domain?: string;
  verifiedAt?: Date;
  failureReason?: string;
}

export interface PermissionInfo {
  requested: string[];
  safe: string[];
  dangerous: string[];
  reviewNeeded: string[];
  riskScore: number;
}

export interface RevocationInfo {
  revoked: boolean;
  reason?: string;
  revokedAt?: Date;
  checkedAt: Date;
}

export interface CheckResult {
  skillId: string;
  publisher: PublisherInfo;
  permissions: PermissionInfo;
  revocation: RevocationInfo;
  risk: RiskLevel;
}

export interface CheckOptions {
  manifest?: {
    permissions?: string[];
  };
  /** Skip real DNS verification (for testing) */
  mockVerified?: boolean;
  mockRevoked?: boolean;
  /** Skip DNS lookup entirely (offline mode) */
  skipDnsVerification?: boolean;
  /** Options passed to verifyPublisher */
  verifyOptions?: VerifyOptions;
}

export async function checkSkill(
  skillId: string,
  options?: CheckOptions
): Promise<CheckResult> {
  // Parse skill identifier
  const parsed = parseSkillIdentifier(skillId);

  // Get publisher info
  const publisher = await getPublisherInfo(parsed.publisher, options);

  // Get permissions from manifest
  const requestedPermissions = options?.manifest?.permissions ?? [];
  const permissionAnalysis = analyzePermissions(requestedPermissions);

  const permissions: PermissionInfo = {
    requested: requestedPermissions,
    safe: permissionAnalysis.safe,
    dangerous: permissionAnalysis.dangerous,
    reviewNeeded: permissionAnalysis.reviewNeeded,
    riskScore: permissionAnalysis.riskScore,
  };

  // Check revocation status
  const revocation = await checkRevocation(skillId, options);

  // Calculate overall risk
  const risk = calculateRisk(publisher, permissions, revocation);

  return {
    skillId,
    publisher,
    permissions,
    revocation,
    risk,
  };
}

async function getPublisherInfo(
  publisherName: string | undefined,
  options?: CheckOptions
): Promise<PublisherInfo> {
  const name = publisherName ?? 'unknown';

  // Handle mock verification for testing (backwards compatible)
  if (options?.mockVerified !== undefined) {
    return {
      name,
      verified: options.mockVerified,
      verificationMethod: options.mockVerified ? 'dns' : 'none',
    };
  }

  // Skip DNS verification if requested (offline mode)
  if (options?.skipDnsVerification) {
    return {
      name,
      verified: false,
      verificationMethod: 'none',
      failureReason: 'DNS verification skipped (offline mode)',
    };
  }

  // Perform real DNS verification
  const verification = await verifyPublisher(name, options?.verifyOptions);

  return {
    name,
    verified: verification.verified,
    verificationMethod: verification.method,
    domain: verification.domain,
    verifiedAt: verification.verifiedAt,
    failureReason: verification.failureReason,
  };
}

async function checkRevocation(
  skillId: string,
  options?: CheckOptions
): Promise<RevocationInfo> {
  const checkedAt = new Date();

  // Handle mock revocation for testing
  if (options?.mockRevoked) {
    return {
      revoked: true,
      reason: 'Skill has been revoked for security reasons',
      revokedAt: new Date(),
      checkedAt,
    };
  }

  // Known revoked skills (in production, this would query a revocation list)
  const revokedSkills = new Set(['@malicious/bad-skill']);

  const revoked = revokedSkills.has(skillId);

  return {
    revoked,
    reason: revoked ? 'Skill has been revoked for security reasons' : undefined,
    revokedAt: revoked ? new Date() : undefined,
    checkedAt,
  };
}

function calculateRisk(
  publisher: PublisherInfo,
  permissions: PermissionInfo,
  revocation: RevocationInfo
): RiskLevel {
  // Critical: skill is revoked
  if (revocation.revoked) {
    return 'critical';
  }

  // High: dangerous permissions
  if (permissions.dangerous.length > 0) {
    return 'high';
  }

  // Medium: unverified publisher or permissions needing review
  if (!publisher.verified || permissions.reviewNeeded.length > 0) {
    return 'medium';
  }

  // Low: verified publisher with safe permissions
  return 'low';
}
