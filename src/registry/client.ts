/**
 * OpenA2A Registry client for posting scan results.
 *
 * Maps HackMyAgent scan findings to the registry's ScanResult format
 * and POSTs them to the registry callback endpoint.
 */

import { createHash } from 'crypto';
import type { SecurityFinding, Severity } from '../hardening';
import { assertRedactionProvenance } from '../hardening/finding-emit';
import type { AttackReport } from '../attack';
import { countsAgainstScore, isMeasured } from '../ui/verdict-band';
import { wireStatus, type SettledOutcome } from '../hardening/settled-outcome';

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

/** Unified publish payload matching POST /api/v1/trust/publish contract */
export interface UnifiedPublishPayload {
  name: string;
  /**
   * Composite as the CLI rendered it, including the #259 verdict-band clamp.
   * This is the signed figure (see the strong canonical in `publish.ts`), so
   * it must be the same number the terminal and `--json` show.
   */
  score: number;
  /**
   * Pre-clamp composite (#259). Same rationale as `subReports.soul.rawScore`
   * under #206: without both fields a dashboard plotting history cannot tell
   * "the scoring rule changed across HMA versions" from "this agent got
   * worse." Absent when nothing was clamped.
   */
  rawScore?: number;
  /** True when `score < rawScore` because the verdict is fail-direction (#259). */
  scoreClamped?: boolean;
  maxScore: number;
  tool: string;
  toolVersion: string;
  findings: UnifiedFinding[];
  scanTimestamp: string;
  verdict: 'pass' | 'warn' | 'fail';
  type?: string;
  version?: string;
  /**
   * Settled-outcome extras (#464): present exactly when the publish carries a
   * settled `secure` run behind it. Typed counts the server can trust instead
   * of re-deriving from the narrowed `findings[]`, the measurement
   * disclosure, and identity-only suppression rows. The server drops unknown
   * fields today (measured: every handler binds with plain json.Unmarshal);
   * the Registry-side typed columns and the 422 on `measured: false` are the
   * R1 migration, owned in opena2a-registry.
   */
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  measured?: boolean;
  exitCode?: number;
  coverage?: { measured: boolean; examined: number; total: number; unit: string; unreadableInputs?: unknown };
  suppressed?: Array<{ checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }>;
  outOfScope?: Array<{ checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }>;
  schemaVersion?: number;
  /** Ed25519 signature (base64) — moved from headers to body */
  signature?: string;
  /** Public key of the signer. PEM for the legacy claimed-agent path; raw base64 for
   *  the first-party scanner path (the registry allowlist expects a raw 32-byte key). */
  publicKey?: string;
  /** Agent identity ID */
  agentId?: string;
  /**
   * Provenance class. Privileged values (first_party_scanner|ci|partner) are honored by
   * the registry ONLY when signature/publicKey/nonce/signedAt prove an allowlisted
   * first-party key signed the strong canonical. Unset → community (fail-closed).
   */
  source?: string;
  /** Single-use anti-replay nonce (first-party scanner path). */
  nonce?: string;
  /** Unix time in seconds at signing (first-party scanner path). */
  signedAt?: number;
  /** Sub-reports from different scan types (hardening, attack, soul, oasb) */
  subReports?: Record<string, unknown>;
  /** CAAT tree hash for deduplication */
  treeHash?: string;
  /** SHA-256 content hash */
  contentHash?: string;
}

export interface UnifiedFinding {
  checkId: string;
  name: string;
  severity: string;
  passed: boolean;
  message: string;
  category?: string;
  attackClass?: string;
}

export interface RegistryConfig {
  registryUrl: string;
  apiKey: string;
  atcToken?: string; // CBOR ATC token (base64url). If set, prefer ATC auth over Bearer.
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
   * Returns the Authorization header value: ATC token if available, otherwise Bearer.
   */
  private getAuthHeader(): string {
    if (this.config.atcToken) {
      return `ATC ${this.config.atcToken}`;
    }
    return `Bearer ${this.config.apiKey}`;
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
        'Authorization': this.getAuthHeader(),
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
        console.error('Registry: rate limited. Try again in a few minutes, or use --no-registry to skip registry checks.');
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
   * Publish scan results via the unified /api/v1/trust/publish endpoint.
   * Falls back to the legacy /api/v1/registry/community/scan-result on 404.
   * Signature and publicKey are sent in the body (not headers).
   */
  async reportPublishResult(
    payload: UnifiedPublishPayload,
    scanToken?: string,
  ): Promise<{ scanId: string; profileUrl: string; status: string; publishId?: string }> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'HackMyAgent-CLI/ATP-Publish',
    };

    if (scanToken) {
      headers['X-Scan-Token'] = scanToken;
    }

    const body = JSON.stringify(payload);

    // Try unified endpoint first
    const unifiedUrl = `${this.config.registryUrl}/api/v1/trust/publish`;
    try {
      const response = await fetch(unifiedUrl, {
        method: 'POST',
        headers,
        body,
        signal: AbortSignal.timeout(10000),
      });

      if (response.ok) {
        const result = await response.json() as Record<string, unknown>;
        return {
          scanId: payload.scanTimestamp,
          profileUrl: (result.profileUrl as string) || `${this.config.registryUrl}/agents/${payload.name}`,
          status: (result.consensusStatus as string) || 'accepted',
          publishId: result.publishId as string | undefined,
        };
      }

      // Fall back to legacy endpoint on 404
      if (response.status === 404) {
        return this.reportPublishResultLegacy(payload, scanToken);
      }

      const errBody = await response.text().catch(() => '');
      throw new Error(`Registry publish failed (${response.status}): ${errBody}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Registry publish failed')) {
        throw err;
      }
      // Network error — try legacy endpoint
      return this.reportPublishResultLegacy(payload, scanToken);
    }
  }

  /**
   * Legacy fallback: POST to /api/v1/registry/community/scan-result.
   * Maps unified payload back to the old CommunityScanPayload format.
   */
  private async reportPublishResultLegacy(
    payload: UnifiedPublishPayload,
    scanToken?: string,
  ): Promise<{ scanId: string; profileUrl: string; status: string }> {
    const url = `${this.config.registryUrl}/api/v1/registry/community/scan-result`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'HackMyAgent-CLI/ATP-Publish',
    };

    if (scanToken) {
      headers['X-Scan-Token'] = scanToken;
    }
    if (payload.signature) {
      headers['X-Agent-Signature'] = payload.signature;
    }
    if (payload.publicKey) {
      headers['X-Agent-Public-Key'] = payload.publicKey;
    }

    // Map unified format back to legacy CommunityScanPayload
    const legacyPayload: Record<string, unknown> = {
      packageName: payload.name,
      packageType: payload.type,
      scanId: `hma-publish-${Date.now()}`,
      status: payload.verdict === 'fail' ? 'failed' : payload.verdict === 'warn' ? 'warnings' : 'passed',
      completedAt: payload.scanTimestamp,
      vulnerabilities: payload.findings.filter(f => !f.passed).map(f => ({
        id: f.checkId,
        severity: f.severity,
        title: f.name,
        description: f.message,
      })),
      criticalCount: payload.findings.filter(f => !f.passed && f.severity === 'critical').length,
      highCount: payload.findings.filter(f => !f.passed && f.severity === 'high').length,
      mediumCount: payload.findings.filter(f => !f.passed && f.severity === 'medium').length,
      lowCount: payload.findings.filter(f => !f.passed && f.severity === 'low').length,
      rawReport: payload.subReports,
    };

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(legacyPayload),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Registry publish failed (${response.status}): ${body}`);
    }

    const result = await response.json() as Record<string, unknown>;
    return {
      scanId: (result.scanId as string) || legacyPayload.scanId as string,
      profileUrl: (result.profileUrl as string) || `${this.config.registryUrl}/agents/${payload.name}`,
      status: (result.status as string) || 'accepted',
    };
  }

  /**
   * Submit a CI scan result to the CAAT pipeline endpoint.
   * Signs the payload with HMAC-SHA256 using the provided secret.
   * Returns trust impact information from the registry.
   */
  async submitCIScanResult(params: CIScanResultParams): Promise<{ valid: boolean; trustImpact: string }> {
    const { createHmac } = await import('crypto');
    const canonical = [
      params.scanId, params.packageName, params.packageType || '',
      params.version || '', params.status,
      params.criticalCount, params.highCount, params.mediumCount, params.lowCount,
      params.contentHash,
    ].join('|');
    const hmacSignature = createHmac('sha256', params.hmacSecret)
      .update(canonical).digest('hex');

    const { hmacSecret: _, ...payloadWithoutSecret } = params;
    const response = await fetch(`${this.config.registryUrl}/api/v1/registry/ci/scan-result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'HackMyAgent-CLI/CI',
      },
      body: JSON.stringify({ ...payloadWithoutSecret, hmacSignature }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`CI scan result submission failed (${response.status}): ${body}`);
    }

    return response.json() as Promise<{ valid: boolean; trustImpact: string }>;
  }
}

/**
 * Build a ScanReportPayload from HMA hardening scan results.
 */
export function buildScanReport(
  versionId: string,
  findings: SecurityFinding[],
  settled?: SettledOutcome,
): ScanReportPayload {
  assertRedactionProvenance(findings, 'registry-scan-report');
  const failed = findings.filter(isMeasured).filter(f => countsAgainstScore(f));

  // #464 — with a settled record the counts and status describe the RUN and
  // are READ from it; the local derivation over the (suppression-narrowed)
  // list remains only for callers with no settled `secure` run behind them.
  const counts = settled ? settled.counts : countBySeverity(failed);
  const status = settled ? wireStatus(settled) : deriveStatus(counts);

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
      // #464 — the settled record rides as ONE object built from the
      // in-memory record, never re-assembled from a document.
      ...(settled ? { settledOutcome: settled } : {}),
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
  settled?: SettledOutcome,
): CommunityScanPayload {
  assertRedactionProvenance(findings, 'registry-community-report');
  const failed = findings.filter(isMeasured).filter(f => countsAgainstScore(f));
  // Only send package-relevant findings to registry — local dev hygiene
  // checks (git, permissions, env, IDE config) don't belong on a package page
  const registryFindings = failed.filter(isRegistryRelevant);
  // #464 — with a settled record the counts and status describe the RUN and
  // are READ from it; the vulnerability list above stays the display subset.
  const counts = settled ? settled.counts : countBySeverity(registryFindings);
  const status = settled ? wireStatus(settled) : deriveStatus(counts);

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
      // #464 — the settled record rides as ONE object built from the
      // in-memory record, never re-assembled from a document.
      ...(settled ? { settledOutcome: settled } : {}),
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

/** Parameters for submitting a CI scan result via the CAAT pipeline */
export interface CIScanResultParams {
  packageName: string;
  packageType?: string;
  version?: string;
  repoUrl: string;
  scanId: string;
  status: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  contentHash: string;
  scannerVersion: string;
  hmacSecret: string;
  rawReport?: Record<string, unknown>;
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
