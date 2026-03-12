/**
 * OpenA2A Registry client for posting scan results.
 *
 * Maps HackMyAgent scan findings to the registry's ScanResult format
 * and POSTs them to the registry callback endpoint.
 */

import { createHash } from 'crypto';
import type { SecurityFinding, Severity } from '../hardening';
import type { AttackReport } from '../attack';

// Registry ScanResult format (must match hackmyagent_service.go:175-200)
export interface ScanReportPayload {
  versionId: string;
  scanId: string;
  status: 'passed' | 'failed' | 'warnings' | 'error';
  completedAt: string;
  vulnerabilities: VulnerabilityFinding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  observedCapabilities: string[];
  observedExternalApis: string[];
  capabilityMismatch: boolean;
  behavioralFindings: BehavioralFinding[];
  behavioralScore: number;
  rawReport: Record<string, unknown>;
  // ATP publish extensions (optional, included when --publish is used)
  /** OASB benchmark compliance percentage (0-100) */
  oasbCompliance?: number;
  /** OASB benchmark rating */
  oasbRating?: string;
  /** OASB L1 compliance percentage */
  oasbL1?: number;
  /** OASB L2 compliance percentage */
  oasbL2?: number;
  /** OASB L3 compliance percentage */
  oasbL3?: number;
  /** SOUL governance score (0-100) */
  soulScore?: number;
  /** SOUL conformance level */
  soulConformance?: string;
  /** SOUL agent tier */
  soulAgentTier?: string;
  /** Attack risk score (0-100) */
  attackRiskScore?: number;
  /** Attack risk rating */
  attackRiskRating?: string;
  /** Total attack payloads tested */
  attackTotal?: number;
  /** Number of successful attacks */
  attackSucceeded?: number;
}

interface VulnerabilityFinding {
  id: string;
  severity: string;
  title: string;
  description: string;
  package?: string;
  version?: string;
  fixedIn?: string;
  cves?: string[];
  cvss?: number;
}

interface BehavioralFinding {
  type: string;
  severity: string;
  description: string;
  evidence?: string;
}

// Community scan result format — identifies packages by name, no auth needed
export interface CommunityScanPayload {
  packageName: string;
  packageType?: string;
  version?: string;
  scanId: string;
  status: 'passed' | 'failed' | 'warnings' | 'error';
  completedAt: string;
  vulnerabilities: VulnerabilityFinding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  rawReport?: Record<string, unknown>;
  contentHash?: string;
}

export interface RegistryConfig {
  registryUrl: string;
  apiKey: string;
}

export interface RegistryPackage {
  id: string;
  publisherId: string;
  name: string;
  packageType: string;
}

export class RegistryClient {
  private config: RegistryConfig;

  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /**
   * Post scan results to registry callback endpoint.
   */
  async reportScanResult(payload: ScanReportPayload): Promise<void> {
    const url = `${this.config.registryUrl}/internal/scan-result`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.config.apiKey}`,
        'User-Agent': 'HackMyAgent-CLI',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(
        `Registry report failed (${response.status}): ${body}`
      );
    }
  }

  /**
   * Request a short-lived scan token for community scan submission.
   * Returns the token response on success, or null on failure (never throws).
   */
  async requestScanToken(
    packageName: string,
    options?: { packageType?: string; version?: string },
  ): Promise<{ scanToken: string; tokenId: string; expiresIn: string } | null> {
    const url = `${this.config.registryUrl}/api/v1/registry/community/request-scan-token`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'HackMyAgent-CLI',
        },
        body: JSON.stringify({
          packageName,
          packageType: options?.packageType,
          version: options?.version,
        }),
      });

      if (response.status === 404) {
        // Package not registered yet -- silently return null
        return null;
      }

      if (response.status === 429) {
        console.error('Registry: rate limited. Try again in a few minutes, or use --skip-registry to skip registry checks.');
        return null;
      }

      if (!response.ok) {
        const body = await response.text().catch(() => '');
        console.error(`Registry: scan token request failed (${response.status}): ${body}`);
        return null;
      }

      return await response.json() as { scanToken: string; tokenId: string; expiresIn: string };
    } catch {
      console.error('Registry: scan token request failed (network error)');
      return null;
    }
  }

  /**
   * Post community scan results with optional scan token.
   * Returns { status: 'accepted' | 'unknown_package' | 'failed' }.
   * Never throws — registry errors are non-fatal for the user's scan.
   */
  async reportCommunityResult(
    payload: CommunityScanPayload,
    scanToken?: string,
  ): Promise<{ status: string; message?: string; code?: string }> {
    const url = `${this.config.registryUrl}/api/v1/registry/community/scan-result`;
    const body = JSON.stringify(payload);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'HackMyAgent-CLI',
    };

    if (scanToken) {
      headers['X-Scan-Token'] = scanToken;
    }

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body,
      });

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({})) as Record<string, unknown>;
        return {
          status: 'failed',
          message: (errBody.message as string) || `HTTP ${response.status}`,
          code: errBody.code as string | undefined,
        };
      }

      return await response.json() as { status: string; message?: string };
    } catch {
      return { status: 'failed', message: 'Network error' };
    }
  }

  /**
   * Look up package info from registry.
   */
  async getPackage(
    publisherName: string,
    packageType: string,
    name: string,
  ): Promise<RegistryPackage | null> {
    const url = `${this.config.registryUrl}/api/v1/registry/${packageType}/${name}?publisher=${publisherName}`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'HackMyAgent-CLI',
      },
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`Registry lookup failed (${response.status})`);
    }

    return response.json() as Promise<RegistryPackage>;
  }

  /**
   * Post scan results as a claimed agent via ATP --publish flow.
   * Uses Ed25519 signature for authentication.
   * Returns the scan ID and profile URL on success.
   */
  async reportPublishResult(
    payload: CommunityScanPayload & {
      oasbCompliance?: number;
      oasbRating?: string;
      oasbL1?: number;
      oasbL2?: number;
      oasbL3?: number;
      soulScore?: number;
      soulConformance?: string;
      soulAgentTier?: string;
      attackRiskScore?: number;
      attackRiskRating?: string;
      attackTotal?: number;
      attackSucceeded?: number;
      signature?: string;
      publicKey?: string;
    },
  ): Promise<{ scanId: string; profileUrl: string; status: string }> {
    const url = `${this.config.registryUrl}/api/v1/registry/community/scan-result`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'HackMyAgent-CLI/ATP-Publish',
    };

    if (payload.signature) {
      headers['X-Agent-Signature'] = payload.signature;
    }
    if (payload.publicKey) {
      headers['X-Agent-Public-Key'] = payload.publicKey;
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Registry publish failed (${response.status}): ${body}`);
    }

    const result = await response.json() as Record<string, unknown>;
    return {
      scanId: (result.scanId as string) || payload.scanId,
      profileUrl: (result.profileUrl as string) || `${this.config.registryUrl}/agents/${payload.packageName}`,
      status: (result.status as string) || 'accepted',
    };
  }
}

/**
 * Build a ScanReportPayload from HMA hardening scan results.
 */
export function buildScanReport(
  versionId: string,
  findings: SecurityFinding[],
): ScanReportPayload {
  const failed = findings.filter(f => !f.passed && !f.fixed);

  const counts = countBySeverity(failed);
  const status = deriveStatus(counts);

  // Map failed findings to vulnerability format
  const vulnerabilities: VulnerabilityFinding[] = failed.map(f => ({
    id: f.checkId,
    severity: f.severity,
    title: f.name,
    description: f.description,
  }));

  // Extract observed capabilities from capability-related checks
  const observedCapabilities: string[] = [];
  for (const f of findings) {
    if (f.checkId.startsWith('FS-') && !f.passed) observedCapabilities.push('filesystem');
    if (f.checkId.startsWith('NET-') && !f.passed) observedCapabilities.push('network');
    if (f.checkId.startsWith('SHELL-') && !f.passed) observedCapabilities.push('shell_exec');
  }

  return {
    versionId,
    scanId: `hma-${Date.now()}`,
    status,
    completedAt: new Date().toISOString(),
    vulnerabilities,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    observedCapabilities: [...new Set(observedCapabilities)],
    observedExternalApis: [],
    capabilityMismatch: false,
    behavioralFindings: [],
    behavioralScore: 0,
    rawReport: {
      generator: 'hackmyagent',
      totalFindings: findings.length,
      failedFindings: failed.length,
    },
  };
}

/**
 * Build a ScanReportPayload from HMA attack results.
 */
export function buildAttackReport(
  versionId: string,
  report: AttackReport,
): ScanReportPayload {
  const vulnerabilities: VulnerabilityFinding[] = report.results
    .filter(r => r.success)
    .map(r => ({
      id: r.payload.id,
      severity: r.payload.severity,
      title: `${r.payload.category}: ${r.payload.id}`,
      description: r.response?.substring(0, 500) || 'Attack succeeded',
    }));

  const counts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  };

  const status = deriveStatus(counts);

  return {
    versionId,
    scanId: `hma-attack-${Date.now()}`,
    status,
    completedAt: new Date().toISOString(),
    vulnerabilities,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    observedCapabilities: [],
    observedExternalApis: [],
    capabilityMismatch: false,
    behavioralFindings: [],
    behavioralScore: 0,
    rawReport: {
      generator: 'hackmyagent-attack',
      target: report.target,
      riskRating: report.riskRating,
      totalPayloads: report.summary.total,
      successfulAttacks: report.summary.successful,
    },
  };
}

/**
 * Build a CommunityScanPayload from HMA hardening scan results.
 * Used for auto-publishing to the community endpoint (no version ID needed).
 */
export function buildCommunityReport(
  packageName: string,
  findings: SecurityFinding[],
  options?: { packageType?: string; version?: string },
): CommunityScanPayload {
  const failed = findings.filter(f => !f.passed && !f.fixed);
  // Only send package-relevant findings to registry — local dev hygiene
  // checks (git, permissions, env, IDE config) don't belong on a package page
  const registryFindings = failed.filter(isRegistryRelevant);
  const counts = countBySeverity(registryFindings);
  const status = deriveStatus(counts);

  const vulnerabilities: VulnerabilityFinding[] = registryFindings.map(f => ({
    id: f.checkId,
    severity: f.severity,
    title: f.name,
    description: f.description,
  }));

  const localOnly = failed.length - registryFindings.length;
  const payload: CommunityScanPayload = {
    packageName,
    packageType: options?.packageType,
    version: options?.version,
    scanId: `hma-community-${Date.now()}`,
    status,
    completedAt: new Date().toISOString(),
    vulnerabilities,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    rawReport: {
      generator: 'hackmyagent',
      totalFindings: findings.length,
      failedFindings: failed.length,
      registryRelevantFindings: registryFindings.length,
      localOnlyFindings: localOnly,
    },
  };
  payload.contentHash = computeContentHash(payload);
  return payload;
}

/**
 * Build a CommunityScanPayload from HMA attack results.
 */
export function buildCommunityAttackReport(
  packageName: string,
  report: AttackReport,
  options?: { packageType?: string; version?: string },
): CommunityScanPayload {
  const vulnerabilities: VulnerabilityFinding[] = report.results
    .filter(r => r.success)
    .map(r => ({
      id: r.payload.id,
      severity: r.payload.severity,
      title: `${r.payload.category}: ${r.payload.id}`,
      description: r.response?.substring(0, 500) || 'Attack succeeded',
    }));

  const counts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  };

  const status = deriveStatus(counts);

  const payload: CommunityScanPayload = {
    packageName,
    packageType: options?.packageType,
    version: options?.version,
    scanId: `hma-attack-community-${Date.now()}`,
    status,
    completedAt: new Date().toISOString(),
    vulnerabilities,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    rawReport: {
      generator: 'hackmyagent-attack',
      target: report.target,
      riskRating: report.riskRating,
      totalPayloads: report.summary.total,
      successfulAttacks: report.summary.successful,
    },
  };
  payload.contentHash = computeContentHash(payload);
  return payload;
}

function countBySeverity(findings: { severity: Severity | string }[]): {
  critical: number;
  high: number;
  medium: number;
  low: number;
} {
  return {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };
}

function deriveStatus(counts: {
  critical: number;
  high: number;
  medium: number;
  low: number;
}): 'passed' | 'failed' | 'warnings' {
  if (counts.critical > 0 || counts.high > 0) return 'failed';
  if (counts.medium > 0 || counts.low > 0) return 'warnings';
  return 'passed';
}

/**
 * Categories that are relevant to a package listing on the registry.
 * Local-only categories (git, permissions, environment, logging, claude-code, cursor, vscode)
 * are filtered out — they describe local dev setup, not package security.
 */
const LOCAL_ONLY_CATEGORIES = new Set([
  'git',
  'permissions',
  'environment',
  'logging',
  'claude-code',
  'cursor',
  'vscode',
]);

function isRegistryRelevant(finding: SecurityFinding): boolean {
  return !LOCAL_ONLY_CATEGORIES.has(finding.category);
}

/**
 * Compute SHA-256 content hash from canonical payload fields.
 * Must match the server-side format: scanId|packageName|packageType|version|status|critical|high|medium|low
 */
function computeContentHash(payload: CommunityScanPayload): string {
  const canonical = [
    payload.scanId,
    payload.packageName,
    payload.packageType || '',
    payload.version || '',
    payload.status,
    payload.criticalCount,
    payload.highCount,
    payload.mediumCount,
    payload.lowCount,
  ].join('|');
  return createHash('sha256').update(canonical).digest('hex');
}
