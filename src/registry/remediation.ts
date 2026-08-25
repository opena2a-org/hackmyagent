import type { SecurityFinding } from '../hardening/security-check.js';
import { countsAgainstScore, confirmedFix } from '../ui/verdict-band';

interface RemediationReport {
  findingId: string;
  source: string;
  sourceEventId: string;
  agentIdentifier: string;
  initialScore?: number;
  initialSeverity: string;
  metadata?: Record<string, unknown>;
}

interface RemediationUpdate {
  findingId: string;
  agentIdentifier: string;
  scanId: string;
  rescanScore: number;
}

/**
 * Report fixed findings to the Registry remediation tracking endpoint.
 * Called after a scan+fix cycle when findings have been remediated.
 */
export async function reportRemediation(
  registryUrl: string,
  scanId: string,
  packageName: string,
  findings: SecurityFinding[],
  score: number,
): Promise<void> {
  // Only fixes that actually landed. `f.fixed || f.fixVerified` POSTed a
  // disproved fix to `/remediation/remediated` while `reportFindings` POSTed
  // the same finding to `/remediation/track` as still open — one call, two
  // contradictory claims about the same checkId. (`|| f.fixVerified` was also
  // dead: `fixed` is already true wherever `fixVerified` is set.)
  const fixedFindings = findings.filter(f => confirmedFix(f));

  if (fixedFindings.length === 0) {
    return;
  }

  const endpoint = `${registryUrl}/api/v1/remediation/remediated`;

  for (const finding of fixedFindings) {
    try {
      const update: RemediationUpdate = {
        findingId: finding.checkId,
        agentIdentifier: packageName,
        scanId,
        rescanScore: score,
      };

      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(update),
      });
    } catch {
      // Non-blocking
    }
  }
}

/**
 * Report new findings to the Registry remediation tracking endpoint.
 * Called after a scan discovers vulnerabilities.
 */
export async function reportFindings(
  registryUrl: string,
  scanId: string,
  packageName: string,
  findings: SecurityFinding[],
  score: number,
): Promise<void> {
  const failedFindings = findings.filter(f => countsAgainstScore(f));

  if (failedFindings.length === 0) {
    return;
  }

  const endpoint = `${registryUrl}/api/v1/remediation/track`;

  for (const finding of failedFindings) {
    try {
      const report: RemediationReport = {
        findingId: finding.checkId,
        source: 'hma_scan',
        sourceEventId: scanId,
        agentIdentifier: packageName,
        initialScore: score,
        initialSeverity: finding.severity,
        metadata: {
          category: finding.category,
          fixable: finding.fixable,
          file: finding.file,
        },
      };

      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(report),
      });
    } catch {
      // Non-blocking
    }
  }
}
