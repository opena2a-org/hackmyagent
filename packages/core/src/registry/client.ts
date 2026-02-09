/**
 * OpenA2A Registry client for posting scan results.
 *
 * Maps HackMyAgent scan findings to the registry's ScanResult format
 * and POSTs them to the registry callback endpoint.
 */

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
    const url = `${this.config.registryUrl}/api/v1/registry/internal/scan-result`;

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
