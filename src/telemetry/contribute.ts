/**
 * Community Contribution Module
 *
 * Delegates queue, flush, and contributor token operations to
 * @opena2a/contribute. Retains HMA-specific logic for building
 * scan events from SecurityFinding arrays (ecosystem detection,
 * finding-to-summary conversion).
 *
 * Queue file: ~/.opena2a/contribute-queue.json
 * Endpoint:   POST api.oa2a.org/api/v1/contribute
 *
 * PRIVACY: Only summary statistics are sent (totalChecks, passed,
 * severity counts, score, verdict). No file paths, no source code,
 * no raw finding descriptions, no PII.
 */

import {
  getContributorToken as sharedGetContributorToken,
  queueEvent as sharedQueueEvent,
  shouldFlush as sharedShouldFlush,
  buildBatch as sharedBuildBatch,
  clearQueue as sharedClearQueue,
  submitBatch,
} from '@opena2a/contribute';
import type {
  ContributionEvent,
  ContributionBatch,
} from '@opena2a/contribute';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { VERSION } from '../index';
import type { SecurityFinding } from '../hardening';

// ---------------------------------------------------------------------------
// Re-export types from @opena2a/contribute
// ---------------------------------------------------------------------------

export type { ContributionEvent, ContributionBatch };

// ---------------------------------------------------------------------------
// Contributor token (delegated to @opena2a/contribute)
// ---------------------------------------------------------------------------

export const getContributorToken = sharedGetContributorToken;

// ---------------------------------------------------------------------------
// Queue operations (delegated to @opena2a/contribute)
// ---------------------------------------------------------------------------

export function queueEvent(event: ContributionEvent): void {
  sharedQueueEvent(event);
}

// ---------------------------------------------------------------------------
// Ecosystem and version detection (HMA-specific)
// ---------------------------------------------------------------------------

function detectEcosystem(directory: string): string {
  if (existsSync(join(directory, 'package.json'))) return 'npm';
  if (
    existsSync(join(directory, 'setup.py')) ||
    existsSync(join(directory, 'pyproject.toml'))
  ) {
    return 'pypi';
  }
  return 'github';
}

function detectPackageVersion(directory: string, ecosystem: string): string {
  try {
    if (ecosystem === 'npm') {
      const pkg = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf-8'));
      return pkg.version || '';
    }
    if (ecosystem === 'pypi') {
      const setupPath = join(directory, 'setup.py');
      if (existsSync(setupPath)) {
        const content = readFileSync(setupPath, 'utf-8');
        const match = content.match(/version\s*=\s*['"]([^'"]+)['"]/);
        if (match) return match[1];
      }
    }
  } catch {
    // Non-fatal: version detection is best-effort
  }
  return '';
}

// ---------------------------------------------------------------------------
// Build contribution event from scan findings (HMA-specific adapter)
// ---------------------------------------------------------------------------

function computeVerdict(findings: SecurityFinding[]): string {
  const critical = findings.filter(f => !f.passed && f.severity === 'critical').length;
  const high = findings.filter(f => !f.passed && f.severity === 'high').length;
  if (critical > 0) return 'fail';
  if (high > 0) return 'warn';
  return 'pass';
}

/**
 * Build a ContributionEvent from HMA scan findings.
 *
 * Converts the detailed finding list into an anonymized summary:
 * only counts and severity distribution, no file paths or descriptions.
 */
export function buildScanEvent(
  packageName: string,
  directory: string,
  findings: SecurityFinding[],
  durationMs: number,
): ContributionEvent {
  const ecosystem = detectEcosystem(directory);
  const version = detectPackageVersion(directory, ecosystem);

  const total = findings.length;
  const passed = findings.filter(f => f.passed).length;
  const failed = findings.filter(f => !f.passed);

  return {
    type: 'scan_result',
    tool: 'hackmyagent',
    toolVersion: VERSION,
    timestamp: new Date().toISOString(),
    package: {
      name: packageName,
      version: version || undefined,
      ecosystem,
    },
    scanSummary: {
      totalChecks: total,
      passed,
      critical: failed.filter(f => f.severity === 'critical').length,
      high: failed.filter(f => f.severity === 'high').length,
      medium: failed.filter(f => f.severity === 'medium').length,
      low: failed.filter(f => f.severity === 'low').length,
      score: total > 0 ? Math.round((passed / total) * 100) : 0,
      verdict: computeVerdict(findings),
      durationMs,
    },
  };
}

// ---------------------------------------------------------------------------
// Submit: queue + flush (delegated to @opena2a/contribute)
// ---------------------------------------------------------------------------

/**
 * Queue a scan result and flush if threshold reached.
 * Non-blocking, best-effort. Never throws.
 */
export async function queueAndMaybeFlush(
  event: ContributionEvent,
  registryUrl?: string,
  verbose?: boolean,
): Promise<void> {
  sharedQueueEvent(event);

  if (sharedShouldFlush()) {
    await flushQueue(registryUrl, verbose);
  }
}

/**
 * Flush queued events to the OpenA2A Registry.
 * Returns true if submission succeeded (or queue was empty).
 */
export async function flushQueue(
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  const batch = sharedBuildBatch();
  if (!batch) return true;

  const success = await submitBatch(batch, registryUrl, verbose);
  if (success) {
    sharedClearQueue();
  }
  return success;
}

// ---------------------------------------------------------------------------
// Legacy compatibility exports (used by existing code)
// ---------------------------------------------------------------------------

/** @deprecated Use buildScanEvent + queueAndMaybeFlush instead. */
export function buildContributionPayloadFromDir(
  packageName: string,
  directory: string,
  findings: SecurityFinding[],
): ContributionEvent {
  return buildScanEvent(packageName, directory, findings, 0);
}

/** @deprecated Use flushQueue instead. */
export async function submitContribution(
  payload: ContributionEvent,
  registryUrl?: string,
): Promise<{ success: boolean; scanId?: string; error?: string }> {
  sharedQueueEvent(payload);
  const ok = await flushQueue(registryUrl);
  return { success: ok };
}

/** @deprecated Kept for backward compat. */
export const generateContributorToken = getContributorToken;
