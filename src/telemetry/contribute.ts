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
import type { SettledOutcome } from '../hardening/settled-outcome';
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

/**
 * Severity ladder for callers with NO settled `secure` record behind them
 * (scan-soul's converted controls, detect). A `secure` run never reaches
 * this: its sites pass the settled record, and the event reads that (#519 —
 * this ladder was the third spelling of one run's verdict across the wires).
 */
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
 *
 * #464/#519 — with a settled record, every figure is READ from it: `score`
 * is the displayed 0-100 (never a passed/total ratio — that ratio reported
 * 0 for any tree with one failure), `verdict` is the settled band, the
 * severity counts are the record's, and `totalChecks` is the count of
 * completed check executions from the run's own coverage record, or OMITTED
 * when the run kept none — a derived stand-in number is worse than no
 * number.
 */
export function buildScanEvent(
  packageName: string,
  directory: string,
  findings: SecurityFinding[],
  durationMs: number,
  settled?: SettledOutcome,
  completedChecks?: number,
): ContributionEvent {
  const ecosystem = detectEcosystem(directory);
  const version = detectPackageVersion(directory, ecosystem);

  const base = {
    type: 'scan_result' as const,
    tool: 'hackmyagent',
    toolVersion: VERSION,
    timestamp: new Date().toISOString(),
    package: {
      name: packageName,
      version: version || undefined,
      ecosystem,
    },
  };

  if (settled) {
    if (settled.verdict === null) {
      // Fail closed: `outboundAllowed` withholds exit-2 runs before this is
      // ever built; a null verdict here is a caller bug, not an event.
      throw new Error('a run at EXIT_UNMEASURED never contributes (#464)');
    }
    return {
      ...base,
      scanSummary: {
        ...(completedChecks !== undefined ? { totalChecks: completedChecks } : {}),
        passed: findings.filter(f => f.passed).length,
        critical: settled.counts.critical,
        high: settled.counts.high,
        medium: settled.counts.medium,
        low: settled.counts.low,
        score: settled.score,
        verdict: settled.verdict,
        durationMs,
      },
    };
  }

  const total = findings.length;
  const passed = findings.filter(f => f.passed).length;
  const failed = findings.filter(f => !f.passed);

  return {
    ...base,
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
// Registry health cache + smart ping
// ---------------------------------------------------------------------------
//
// Pre-flight health check: GET /health (3s timeout) before any flush attempt.
// Cached for HEALTH_CACHE_TTL_MS to avoid hitting /health on every scan.
// Result stored in ~/.opena2a/contribute-health.json.
//
// scan_ping heartbeat: sent once per PING_INTERVAL_MS via /api/v1/contribute.
// Tells the registry "this tool is installed and running" — used for adoption
// analytics. Completely separate from scan_result contribution events.
// Last ping time stored in ~/.opena2a/contribute-ping.json.

const HEALTH_CACHE_TTL_MS = 5 * 60 * 1000;   // 5 minutes
const PING_INTERVAL_MS   = 6 * 60 * 60 * 1000; // 6 hours

interface HealthCache {
  checkedAt: string;
  healthy: boolean;
  status?: string;
}

interface PingState {
  lastPingAt: string;
}

function getHealthCachePath(): string {
  const os = require('os');
  const path = require('path');
  const home = process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
  return path.join(home, 'contribute-health.json');
}

function getPingStatePath(): string {
  const os = require('os');
  const path = require('path');
  const home = process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
  return path.join(home, 'contribute-ping.json');
}

function readHealthCache(): HealthCache | null {
  try {
    const { readFileSync, existsSync } = require('fs');
    const p = getHealthCachePath();
    if (!existsSync(p)) return null;
    const cache: HealthCache = JSON.parse(readFileSync(p, 'utf-8'));
    if (Date.now() - new Date(cache.checkedAt).getTime() > HEALTH_CACHE_TTL_MS) return null;
    return cache;
  } catch {
    return null;
  }
}

function writeHealthCache(healthy: boolean, status?: string): void {
  try {
    const { writeFileSync, mkdirSync } = require('fs');
    const path = require('path');
    const p = getHealthCachePath();
    mkdirSync(path.dirname(p), { recursive: true });
    const cache: HealthCache = { checkedAt: new Date().toISOString(), healthy, status };
    writeFileSync(p, JSON.stringify(cache, null, 2) + '\n', { mode: 0o600 });
  } catch { /* Non-fatal */ }
}

/**
 * Check registry health. Returns true if healthy.
 * Uses a 3-second timeout and caches the result for 5 minutes.
 * Completely silent — never throws, never surfaces to user.
 */
async function checkRegistryHealth(baseUrl: string): Promise<boolean> {
  const cached = readHealthCache();
  if (cached !== null) return cached.healthy;

  try {
    const { request } = await import('node:https');
    const { URL } = await import('node:url');
    const url = new URL('/health', baseUrl);
    const healthy = await new Promise<boolean>((resolve) => {
      const req = request(
        { hostname: url.hostname, port: url.port || 443, path: url.pathname, method: 'GET', timeout: 3000 },
        (res) => {
          let body = '';
          res.on('data', (d: Buffer) => { body += d.toString(); });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(body);
              const ok = res.statusCode === 200 && parsed.status === 'healthy';
              writeHealthCache(ok, parsed.status);
              resolve(ok);
            } catch {
              writeHealthCache(false);
              resolve(false);
            }
          });
        },
      );
      req.on('timeout', () => { req.destroy(); writeHealthCache(false, 'timeout'); resolve(false); });
      req.on('error',   () => { writeHealthCache(false, 'error');   resolve(false); });
      req.end();
    });
    return healthy;
  } catch {
    writeHealthCache(false, 'error');
    return false;
  }
}

/**
 * Send a scan_ping heartbeat event if more than PING_INTERVAL_MS has elapsed.
 * Tells the registry this tool is installed and active — used for adoption stats.
 * Non-blocking, best-effort. Never throws.
 */
async function maybeSendPing(registryUrl: string): Promise<void> {
  try {
    const { readFileSync, writeFileSync, mkdirSync, existsSync } = require('fs');
    const path = require('path');
    const p = getPingStatePath();

    // Check whether ping is due
    if (existsSync(p)) {
      const state: PingState = JSON.parse(readFileSync(p, 'utf-8'));
      if (Date.now() - new Date(state.lastPingAt).getTime() < PING_INTERVAL_MS) return;
    }

    // Build ping event (no scan data — just tool presence signal)
    const pingEvent: ContributionEvent = {
      type: 'scan_ping' as ContributionEvent['type'],
      tool: 'hackmyagent',
      toolVersion: VERSION,
      timestamp: new Date().toISOString(),
      package: { name: '_ping', ecosystem: 'npm' as const },
      scanSummary: { totalChecks: 0, passed: 0, critical: 0, high: 0, medium: 0, low: 0, score: 0, verdict: 'pass', durationMs: 0 },
    };

    sharedQueueEvent(pingEvent);
    // Flush just the ping (force flush regardless of threshold)
    const batch = sharedBuildBatch();
    if (batch) {
      const ok = await submitBatch(batch, registryUrl, false);
      if (ok) {
        sharedClearQueue();
        // Record ping time
        mkdirSync(path.dirname(p), { recursive: true });
        const state: PingState = { lastPingAt: new Date().toISOString() };
        writeFileSync(p, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
      }
    }
  } catch { /* Non-fatal */ }
}

// ---------------------------------------------------------------------------
// Retry state — opportunistic backoff for failed submissions
// ---------------------------------------------------------------------------
//
// Retry intervals (checked when a scan runs — no background timers):
//   attempt 1 fail → retry after  5 minutes
//   attempt 2 fail → retry after  1 hour
//   attempt 3 fail → retry after  8 hours
//   attempt 4+ fail → retry after 24 hours (once daily)
//   after 7 days of continuous failure → drop queue (data is stale)
//
// Stored in ~/.opena2a/contribute-retry.json alongside the queue.
// Completely silent — failure to retry never surfaces to the user.

const RETRY_INTERVALS_MS = [
  5 * 60 * 1000,        // 5 min
  60 * 60 * 1000,       // 1 hour
  8 * 60 * 60 * 1000,   // 8 hours
  24 * 60 * 60 * 1000,  // 24 hours (daily cap)
];
const STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000; // 7 days → drop queue

interface RetryState {
  lastAttemptAt: string;
  nextRetryAt: string;
  retryCount: number;
}

function getRetryStatePath(): string {
  const os = require('os');
  const path = require('path');
  const home = process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
  return path.join(home, 'contribute-retry.json');
}

function readRetryState(): RetryState | null {
  try {
    const { readFileSync, existsSync } = require('fs');
    const p = getRetryStatePath();
    if (!existsSync(p)) return null;
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return null;
  }
}

function writeRetryState(state: RetryState): void {
  try {
    const { writeFileSync, mkdirSync } = require('fs');
    const path = require('path');
    const p = getRetryStatePath();
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  } catch { /* Non-fatal */ }
}

function clearRetryState(): void {
  try {
    const { rmSync, existsSync } = require('fs');
    const p = getRetryStatePath();
    if (existsSync(p)) rmSync(p);
  } catch { /* Non-fatal */ }
}

/** Returns true if enough time has passed to attempt a retry. */
function shouldRetryNow(state: RetryState): boolean {
  const now = Date.now();

  // Drop stale queue — 7 days of failure means data is no longer useful
  if (now - new Date(state.lastAttemptAt).getTime() > STALE_AFTER_MS) {
    sharedClearQueue();
    clearRetryState();
    return false;
  }

  return now >= new Date(state.nextRetryAt).getTime();
}

function recordFailure(previousState: RetryState | null): void {
  const retryCount = (previousState?.retryCount ?? 0) + 1;
  const intervalIndex = Math.min(retryCount - 1, RETRY_INTERVALS_MS.length - 1);
  const delayMs = RETRY_INTERVALS_MS[intervalIndex];

  writeRetryState({
    lastAttemptAt: new Date().toISOString(),
    nextRetryAt: new Date(Date.now() + delayMs).toISOString(),
    retryCount,
  });
}

// ---------------------------------------------------------------------------
// Submit: queue + flush (delegated to @opena2a/contribute)
// ---------------------------------------------------------------------------

const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';

/**
 * Queue a scan result and flush if threshold reached or retry interval elapsed.
 * Sends a ping heartbeat if 6+ hours have elapsed since last ping.
 * Non-blocking, best-effort. Never throws.
 */
export async function queueAndMaybeFlush(
  event: ContributionEvent,
  registryUrl?: string,
  verbose?: boolean,
): Promise<void> {
  const url = registryUrl || DEFAULT_REGISTRY_URL;
  sharedQueueEvent(event);

  // Send ping heartbeat if due (non-blocking, uses its own queue+flush)
  // Only attempt if registry appears healthy (uses cached result)
  maybeSendPing(url).catch(() => { /* Non-fatal */ });

  const retryState = readRetryState();
  const hasPendingRetry = retryState !== null;

  // Flush if: threshold reached, OR a scheduled retry is due
  const shouldFlush = sharedShouldFlush() || (hasPendingRetry && shouldRetryNow(retryState!));
  if (shouldFlush) {
    await flushQueue(url, verbose);
  }
}

/**
 * Flush queued events to the OpenA2A Registry.
 *
 * Pre-flight: checks GET /health before attempting submission.
 * If registry is unhealthy/unreachable: records failure immediately
 * (no wasted network attempt, backoff still advances).
 *
 * On success: clears queue and retry state.
 * On failure: records retry state with backoff interval.
 * Returns true if submission succeeded (or queue was empty).
 */
export async function flushQueue(
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  const url = registryUrl || DEFAULT_REGISTRY_URL;

  const batch = sharedBuildBatch();
  if (!batch) {
    clearRetryState(); // Queue empty — no need to retry
    return true;
  }

  // Pre-flight health check — skip submission if registry is down
  const healthy = await checkRegistryHealth(url);
  if (!healthy) {
    recordFailure(readRetryState());
    return false;
  }

  const priorState = readRetryState();
  const success = await submitBatch(batch, url, verbose);

  if (success) {
    sharedClearQueue();
    clearRetryState();
  } else {
    // Record failure silently — next scan will check the retry schedule
    recordFailure(priorState);
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
