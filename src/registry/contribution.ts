/**
 * Anonymous registry contribution for scan results.
 *
 * When users opt in (--contribute flag), scan results are submitted
 * anonymously to the OpenA2A registry for aggregate security intelligence.
 *
 * What IS sent:
 * - SHA256 hash of scanned artifact (for deduplication, not identification)
 * - Scan type and version
 * - Finding IDs and severities (no file paths or content)
 * - Domain scores (for governance scans)
 * - Agent tier classification
 * - Timestamp and scanner version
 *
 * What is NEVER sent:
 * - File paths, file content, or source code
 * - Usernames, hostnames, or IP addresses
 * - Environment variables or credential values
 * - Directory structure or project names
 */

import * as crypto from 'crypto';

export type ContributionType =
  | 'hardening'        // hackmyagent secure
  | 'governance'       // hackmyagent scan-soul
  | 'mcp-enumeration'  // MCP tool discovery
  | 'skill-check'      // hackmyagent check
  | 'attack'           // hackmyagent attack
  | 'history'          // shell history scan
  | 'scope';           // credential scope discovery

export interface ContributionPayload {
  // Identification (anonymous)
  contributionId: string;           // Random UUID per submission
  artifactHash: string;             // SHA256 of scanned content

  // Scan metadata
  scanType: ContributionType;
  scannerVersion: string;
  scanTimestamp: string;             // ISO 8601
  scanDurationMs?: number;

  // Results (aggregated, no PII)
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;

  // Finding IDs only (no descriptions, no file paths)
  findingIds: string[];              // e.g., ['SHELL-001', 'CRED-003']

  // Score (if applicable)
  score?: number;
  maxScore?: number;
  grade?: string;

  // Governance-specific (if applicable)
  governance?: {
    tier: string;
    domainScores: Array<{
      domain: string;
      score: number;
      controlsPassed: number;
      controlsTotal: number;
    }>;
    criticalFailures: string[];     // Control IDs only
  };

  // MCP-specific (if applicable)
  mcpEnumeration?: {
    serversScanned: number;
    totalTools: number;
    dangerousToolCount: number;
    categories: string[];            // e.g., ['execution', 'filesystem', 'network']
  };

  // Skill-specific (if applicable)
  skillCheck?: {
    riskLevel: string;
    verified: boolean;
    permissionCount: number;
    dangerousPermissions: number;
  };

  // Attack-specific (if applicable)
  attack?: {
    categories: string[];
    payloadsRun: number;
    payloadsBlocked: number;
    payloadsBypassed: number;
    blockRate: number;
  };
}

/**
 * Generate SHA256 hash of content for artifact identification.
 * The hash allows deduplication without revealing content.
 */
export function hashArtifact(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Generate a random contribution ID.
 */
export function generateContributionId(): string {
  return crypto.randomUUID();
}

/**
 * Strip PII from a finding list -- return only check IDs.
 */
export function extractFindingIds(findings: Array<{ checkId: string }>): string[] {
  return [...new Set(findings.map(f => f.checkId))].sort();
}

/**
 * Count findings by severity.
 */
export function countBySeverity(
  findings: Array<{ severity: string; passed?: boolean }>,
): { critical: number; high: number; medium: number; low: number } {
  const failed = findings.filter(f => f.passed === false);
  return {
    critical: failed.filter(f => f.severity === 'critical').length,
    high: failed.filter(f => f.severity === 'high').length,
    medium: failed.filter(f => f.severity === 'medium').length,
    low: failed.filter(f => f.severity === 'low').length,
  };
}

/**
 * Build a contribution payload from hardening scan results.
 */
export function buildHardeningContribution(
  scannerVersion: string,
  artifactContent: string,
  findings: Array<{ checkId: string; severity: string; passed?: boolean }>,
  score: number,
  maxScore: number,
  durationMs?: number,
): ContributionPayload {
  const counts = countBySeverity(findings);
  return {
    contributionId: generateContributionId(),
    artifactHash: hashArtifact(artifactContent),
    scanType: 'hardening',
    scannerVersion,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: durationMs,
    totalFindings: counts.critical + counts.high + counts.medium + counts.low,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    findingIds: extractFindingIds(findings.filter(f => !f.passed)),
    score,
    maxScore,
  };
}

/**
 * Build a contribution payload from governance scan results.
 */
export function buildGovernanceContribution(
  scannerVersion: string,
  artifactContent: string,
  governanceScore: {
    overall: number;
    grade: string;
    tier: string;
    domains: Array<{ domain: string; score: number; controlsPassed: number; controlsTotal: number }>;
    results: Array<{ controlId: string; severity: string; passed: boolean }>;
    criticalFailures: string[];
  },
  durationMs?: number,
): ContributionPayload {
  const failed = governanceScore.results.filter(r => !r.passed);
  const counts = countBySeverity(failed.map(r => ({ severity: r.severity, passed: false })));

  return {
    contributionId: generateContributionId(),
    artifactHash: hashArtifact(artifactContent),
    scanType: 'governance',
    scannerVersion,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: durationMs,
    totalFindings: failed.length,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    findingIds: failed.map(r => r.controlId),
    score: governanceScore.overall,
    maxScore: 100,
    grade: governanceScore.grade,
    governance: {
      tier: governanceScore.tier,
      domainScores: governanceScore.domains.map(d => ({
        domain: d.domain,
        score: d.score,
        controlsPassed: d.controlsPassed,
        controlsTotal: d.controlsTotal,
      })),
      criticalFailures: governanceScore.criticalFailures,
    },
  };
}

/**
 * Build a contribution payload from MCP tool enumeration.
 */
export function buildMcpContribution(
  scannerVersion: string,
  configContent: string,
  serverResults: Array<{
    serverName: string;
    toolCount: number;
    findings: Array<{ checkId: string; severity: string }>;
  }>,
  durationMs?: number,
): ContributionPayload {
  const allFindings = serverResults.flatMap(s => s.findings);
  const counts = countBySeverity(allFindings.map(f => ({ severity: f.severity, passed: false })));

  const categories = new Set<string>();
  for (const f of allFindings) {
    if (f.checkId === 'MCPTOOL-001') categories.add('execution');
    if (f.checkId === 'MCPTOOL-002') categories.add('filesystem');
    if (f.checkId === 'MCPTOOL-003') categories.add('network');
    if (f.checkId === 'MCPTOOL-004') categories.add('credential');
  }

  return {
    contributionId: generateContributionId(),
    artifactHash: hashArtifact(configContent),
    scanType: 'mcp-enumeration',
    scannerVersion,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: durationMs,
    totalFindings: allFindings.length,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    findingIds: [...new Set(allFindings.map(f => f.checkId))].sort(),
    mcpEnumeration: {
      serversScanned: serverResults.length,
      totalTools: serverResults.reduce((sum, s) => sum + s.toolCount, 0),
      dangerousToolCount: allFindings.length,
      categories: [...categories],
    },
  };
}

/**
 * Build a contribution payload from attack scan results.
 */
export function buildAttackContribution(
  scannerVersion: string,
  targetIdentifier: string,
  attackReport: {
    categories: string[];
    totalPayloads: number;
    blocked: number;
    bypassed: number;
    blockRate: number;
  },
  durationMs?: number,
): ContributionPayload {
  return {
    contributionId: generateContributionId(),
    artifactHash: hashArtifact(targetIdentifier),
    scanType: 'attack',
    scannerVersion,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: durationMs,
    totalFindings: attackReport.bypassed,
    criticalCount: 0,
    highCount: attackReport.bypassed,
    mediumCount: 0,
    lowCount: 0,
    findingIds: attackReport.categories,
    attack: {
      categories: attackReport.categories,
      payloadsRun: attackReport.totalPayloads,
      payloadsBlocked: attackReport.blocked,
      payloadsBypassed: attackReport.bypassed,
      blockRate: attackReport.blockRate,
    },
  };
}

/**
 * Submit contribution to registry. Never throws -- contribution failure is non-fatal.
 */
export async function submitContribution(
  registryUrl: string,
  payload: ContributionPayload,
): Promise<{ status: string; message?: string }> {
  try {
    const response = await fetch(`${registryUrl}/api/v1/registry/community/contribute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'HackMyAgent-CLI',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as Record<string, unknown>;
      return { status: 'failed', message: (body.message as string) || `HTTP ${response.status}` };
    }

    return await response.json() as { status: string; message?: string };
  } catch {
    return { status: 'failed', message: 'Network error' };
  }
}
