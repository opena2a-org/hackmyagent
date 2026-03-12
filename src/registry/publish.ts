/**
 * ATP Publish Flow — Push scan results to the OpenA2A Registry.
 *
 * Supports two paths:
 *   1. Claimed agent: reads Ed25519 keypair from ~/.opena2a/keys/, signs payload, full weight (1.0x)
 *   2. Community fallback: no auth, results have lower weight (0.5x)
 *
 * Used by the --publish flag on secure, attack, and scan-soul commands.
 */

import { createHash } from 'crypto';
import type { SecurityFinding, Severity } from '../hardening';
import type { AttackReport } from '../attack';
import type { SoulScanResult } from '../soul';
import type { BenchmarkResult } from '../benchmarks';
import { RegistryClient, type CommunityScanPayload } from './client';

/** Result of reading a keypair from ~/.opena2a/keys/ */
export interface AgentKeypair {
  publicKey: string;
  privateKey: string;
  agentId?: string;
}

/** Composite scan data collected from all scan types for publishing */
export interface PublishScanData {
  packageName: string;
  packageVersion?: string;
  packageType?: string;
  directory: string;
  /** Hardening scan findings (from `secure` command) */
  hardeningFindings?: SecurityFinding[];
  /** Attack scan report (from `attack` command) */
  attackReport?: AttackReport;
  /** SOUL governance scan result (from `scan-soul` command) */
  soulResult?: SoulScanResult;
  /** OASB benchmark result (from `secure -b oasb-1`) */
  oasbResult?: BenchmarkResult;
}

/** Result returned after publishing to registry */
export interface PublishResult {
  success: boolean;
  scanId: string;
  profileUrl: string;
  status: string;
  isCommunity: boolean;
  error?: string;
}

/**
 * Read the agent's Ed25519 keypair from ~/.opena2a/keys/.
 * Returns null if no keypair exists (agent not claimed).
 *
 * The keys directory can be overridden via OPENA2A_HOME env var
 * (defaults to ~/.opena2a).
 */
export function readAgentKeypair(): AgentKeypair | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const os = require('os');

    const opena2aHome = process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
    const keysDir = path.join(opena2aHome, 'keys');
    if (!fs.existsSync(keysDir)) {
      return null;
    }

    const pubKeyPath = path.join(keysDir, 'agent.pub');
    const privKeyPath = path.join(keysDir, 'agent.key');
    const agentIdPath = path.join(keysDir, 'agent-id');

    if (!fs.existsSync(pubKeyPath) || !fs.existsSync(privKeyPath)) {
      return null;
    }

    const publicKey = fs.readFileSync(pubKeyPath, 'utf-8').trim();
    const privateKey = fs.readFileSync(privKeyPath, 'utf-8').trim();
    const agentId = fs.existsSync(agentIdPath)
      ? fs.readFileSync(agentIdPath, 'utf-8').trim()
      : undefined;

    return { publicKey, privateKey, agentId };
  } catch {
    return null;
  }
}

/**
 * Sign a payload string with the agent's Ed25519 private key.
 * Returns the base64-encoded signature, or null if signing fails.
 */
export function signPayload(payload: string, privateKeyPem: string): string | null {
  try {
    const crypto = require('crypto');
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signature = crypto.sign(null, Buffer.from(payload), privateKey);
    return signature.toString('base64');
  } catch {
    return null;
  }
}

/**
 * Build a unified publish payload from scan data.
 * Combines results from hardening, attack, SOUL, and OASB scans.
 */
export function buildPublishPayload(data: PublishScanData): CommunityScanPayload & Record<string, unknown> {
  const scanId = `hma-publish-${Date.now()}`;
  const completedAt = new Date().toISOString();

  // Determine overall status from hardening findings
  let status: 'passed' | 'failed' | 'warnings' | 'error' = 'passed';
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  const vulnerabilities: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
  }> = [];

  if (data.hardeningFindings) {
    const failed = data.hardeningFindings.filter(f => !f.passed && !f.fixed);
    for (const f of failed) {
      if (f.severity === 'critical') criticalCount++;
      else if (f.severity === 'high') highCount++;
      else if (f.severity === 'medium') mediumCount++;
      else if (f.severity === 'low') lowCount++;

      vulnerabilities.push({
        id: f.checkId,
        severity: f.severity,
        title: f.name,
        description: f.description,
      });
    }
  }

  // Incorporate attack results into severity counts
  if (data.attackReport) {
    const successfulAttacks = data.attackReport.results.filter(r => r.success);
    for (const r of successfulAttacks) {
      if (r.payload.severity === 'critical') criticalCount++;
      else if (r.payload.severity === 'high') highCount++;
      else if (r.payload.severity === 'medium') mediumCount++;
      else lowCount++;

      vulnerabilities.push({
        id: r.payload.id,
        severity: r.payload.severity,
        title: `Attack: ${r.payload.category} - ${r.payload.id}`,
        description: r.response?.substring(0, 500) || 'Attack succeeded',
      });
    }
  }

  // Derive overall status
  if (criticalCount > 0 || highCount > 0) status = 'failed';
  else if (mediumCount > 0 || lowCount > 0) status = 'warnings';

  // Build raw report with all scan type data
  const rawReport: Record<string, unknown> = {
    generator: 'hackmyagent',
    publishedVia: 'atp-publish',
  };

  if (data.hardeningFindings) {
    const total = data.hardeningFindings.length;
    const failed = data.hardeningFindings.filter(f => !f.passed && !f.fixed).length;
    rawReport.hardening = {
      totalChecks: total,
      failedChecks: failed,
      passRate: total > 0 ? Math.round(((total - failed) / total) * 100) : 100,
    };
  }

  if (data.attackReport) {
    rawReport.attack = {
      riskScore: data.attackReport.riskScore,
      riskRating: data.attackReport.riskRating,
      totalPayloads: data.attackReport.summary.total,
      successfulAttacks: data.attackReport.summary.successful,
      blockedAttacks: data.attackReport.summary.blocked,
    };
  }

  if (data.soulResult) {
    rawReport.soul = {
      score: data.soulResult.score,
      conformance: data.soulResult.conformance,
      agentTier: data.soulResult.agentTier,
      totalControls: data.soulResult.totalControls,
      totalPassed: data.soulResult.totalPassed,
    };
  }

  if (data.oasbResult) {
    rawReport.oasb = {
      compliance: data.oasbResult.compliance,
      rating: data.oasbResult.rating,
      l1Compliance: data.oasbResult.l1Compliance,
      l2Compliance: data.oasbResult.l2Compliance,
      l3Compliance: data.oasbResult.l3Compliance,
    };
  }

  // Compute content hash
  const canonical = [
    scanId,
    data.packageName,
    data.packageType || '',
    data.packageVersion || '',
    status,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
  ].join('|');
  const contentHash = createHash('sha256').update(canonical).digest('hex');

  const payload: CommunityScanPayload & Record<string, unknown> = {
    packageName: data.packageName,
    packageType: data.packageType,
    version: data.packageVersion,
    scanId,
    status,
    completedAt,
    vulnerabilities,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    rawReport,
    contentHash,
  };

  // Add ATP extension fields
  if (data.oasbResult) {
    payload.oasbCompliance = data.oasbResult.compliance;
    payload.oasbRating = data.oasbResult.rating;
    payload.oasbL1 = data.oasbResult.l1Compliance;
    payload.oasbL2 = data.oasbResult.l2Compliance;
    payload.oasbL3 = data.oasbResult.l3Compliance;
  }

  if (data.soulResult) {
    payload.soulScore = data.soulResult.score;
    payload.soulConformance = data.soulResult.conformance;
    payload.soulAgentTier = data.soulResult.agentTier;
  }

  if (data.attackReport) {
    payload.attackRiskScore = data.attackReport.riskScore;
    payload.attackRiskRating = data.attackReport.riskRating;
    payload.attackTotal = data.attackReport.summary.total;
    payload.attackSucceeded = data.attackReport.summary.successful;
  }

  return payload;
}

/**
 * Publish scan results to the OpenA2A Registry.
 *
 * Flow:
 *   1. Read keypair from ~/.opena2a/keys/ (if claimed)
 *   2. Build unified payload from scan data
 *   3. Sign payload if keypair exists
 *   4. POST to registry (claimed or community path)
 */
export async function publishScanResults(
  data: PublishScanData,
  registryUrl: string,
): Promise<PublishResult> {
  const keypair = readAgentKeypair();
  const isCommunity = !keypair;

  const payload = buildPublishPayload(data);

  // Sign if we have a keypair
  if (keypair) {
    const payloadString = JSON.stringify(payload);
    const signature = signPayload(payloadString, keypair.privateKey);
    if (signature) {
      (payload as Record<string, unknown>).signature = signature;
      (payload as Record<string, unknown>).publicKey = keypair.publicKey;
    }
    if (keypair.agentId) {
      (payload as Record<string, unknown>).agentId = keypair.agentId;
    }
  }

  try {
    const client = new RegistryClient({ registryUrl, apiKey: '' });
    const result = await client.reportPublishResult(payload as any);

    return {
      success: true,
      scanId: result.scanId,
      profileUrl: result.profileUrl,
      status: result.status,
      isCommunity,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      success: false,
      scanId: payload.scanId,
      profileUrl: `${registryUrl}/agents/${data.packageName}`,
      status: 'error',
      isCommunity,
      error: message,
    };
  }
}

/**
 * Format the publish result for terminal output.
 */
export function formatPublishOutput(
  result: PublishResult,
  data: PublishScanData,
  registryUrl: string,
): string {
  const lines: string[] = [];

  if (result.success) {
    lines.push('Published to ' + new URL(registryUrl).hostname);
    lines.push('  Agent: ' + data.packageName);
    lines.push('  Scan ID: ' + result.scanId);
    lines.push('  Status: ' + result.status);

    // Build summary of what was included
    const parts: string[] = [];
    if (data.hardeningFindings) {
      const failed = data.hardeningFindings.filter(f => !f.passed && !f.fixed);
      parts.push(`hardening (${failed.length} finding${failed.length === 1 ? '' : 's'})`);
    }
    if (data.oasbResult) {
      parts.push(`OASB (${data.oasbResult.compliance}% compliance)`);
    }
    if (data.soulResult) {
      parts.push(`SOUL (${data.soulResult.score}/100)`);
    }
    if (data.attackReport) {
      parts.push(`attack (${data.attackReport.riskRating} risk)`);
    }
    if (parts.length > 0) {
      lines.push('  Scans: ' + parts.join(', '));
    }

    lines.push('  Trust impact: score may increase on next recalculation');

    if (result.isCommunity) {
      lines.push('');
      lines.push('  Published as community scan (0.5x weight).');
      lines.push('  Run `opena2a claim` first for full weight (1.0x).');
    }

    lines.push('');
    lines.push('Profile: ' + result.profileUrl);
  } else {
    lines.push('Failed to publish to registry: ' + (result.error || 'unknown error'));
    lines.push('Scan results are still available locally.');
  }

  return lines.join('\n');
}
