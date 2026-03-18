/**
 * Community Contribution Module
 *
 * Queue-based contribution of anonymized HMA scan summaries to the
 * OpenA2A Registry. Compatible with @opena2a/contribute queue format:
 * events queued by HMA are flushed by opena2a-cli and vice versa.
 *
 * Queue file: ~/.opena2a/contribute-queue.json
 * Endpoint:   POST registry.opena2a.org/api/v1/contribute
 *
 * PRIVACY: Only summary statistics are sent (totalChecks, passed,
 * severity counts, score, verdict). No file paths, no source code,
 * no raw finding descriptions, no PII.
 */

import { createHash, randomBytes } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { hostname, type as osType, userInfo } from 'os';
import { join } from 'path';
import { VERSION } from '../index';
import type { SecurityFinding } from '../hardening';

// ---------------------------------------------------------------------------
// Paths and constants
// ---------------------------------------------------------------------------

const REGISTRY_URL = 'https://registry.opena2a.org';
const FLUSH_THRESHOLD = 10;
const MAX_QUEUE_SIZE = 100;
const TIMEOUT_MS = 10_000;

function getOpena2aHome(): string {
  return process.env.OPENA2A_HOME || join(require('os').homedir(), '.opena2a');
}

function ensureDir(): void {
  const dir = getOpena2aHome();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// @opena2a/contribute-compatible types
// ---------------------------------------------------------------------------

/** Matches ContributionEvent from @opena2a/contribute/types. */
export interface ContributionEvent {
  type: 'scan_result' | 'detection' | 'behavior' | 'interaction' | 'adoption';
  tool: string;
  toolVersion: string;
  timestamp: string;
  package?: {
    name: string;
    version?: string;
    ecosystem?: string;
  };
  scanSummary?: {
    totalChecks: number;
    passed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
    verdict: string;
    durationMs: number;
  };
}

/** Matches ContributionBatch from @opena2a/contribute/types. */
export interface ContributionBatch {
  contributorToken: string;
  events: ContributionEvent[];
  submittedAt: string;
}

interface QueueFile {
  events: ContributionEvent[];
  lastFlushAttempt?: string;
}

// ---------------------------------------------------------------------------
// Contributor token (stable per-device, SHA256-hashed)
// ---------------------------------------------------------------------------

export function getContributorToken(): string {
  const home = getOpena2aHome();
  const saltPath = join(home, 'contributor-salt');

  let salt: string;
  if (existsSync(saltPath)) {
    salt = readFileSync(saltPath, 'utf-8').trim();
  } else {
    salt = randomBytes(32).toString('hex');
    ensureDir();
    writeFileSync(saltPath, salt, { mode: 0o600 });
  }

  const input = `${hostname()}|${userInfo().username}|${salt}`;
  return createHash('sha256').update(input).digest('hex');
}

// ---------------------------------------------------------------------------
// Queue operations (compatible with @opena2a/contribute queue format)
// ---------------------------------------------------------------------------

function queuePath(): string {
  return join(getOpena2aHome(), 'contribute-queue.json');
}

function loadQueue(): QueueFile {
  const path = queuePath();
  if (!existsSync(path)) return { events: [] };
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return { events: [] };
  }
}

function saveQueue(queue: QueueFile): void {
  ensureDir();
  writeFileSync(queuePath(), JSON.stringify(queue), { mode: 0o600 });
}

export function queueEvent(event: ContributionEvent): void {
  const queue = loadQueue();
  queue.events.push(event);

  if (queue.events.length > MAX_QUEUE_SIZE) {
    queue.events = queue.events.slice(-MAX_QUEUE_SIZE);
  }

  saveQueue(queue);
}

function shouldFlush(): boolean {
  return loadQueue().events.length >= FLUSH_THRESHOLD;
}

function buildBatch(): ContributionBatch | null {
  const events = loadQueue().events;
  if (events.length === 0) return null;

  return {
    contributorToken: getContributorToken(),
    events,
    submittedAt: new Date().toISOString(),
  };
}

function clearQueue(): void {
  saveQueue({ events: [] });
}

// ---------------------------------------------------------------------------
// Ecosystem and version detection
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
// Map OS type
// ---------------------------------------------------------------------------

function resolveOsType(): string {
  const t = osType();
  if (t === 'Darwin') return 'macos';
  if (t === 'Windows_NT') return 'windows';
  return 'linux';
}

// ---------------------------------------------------------------------------
// Build contribution event from scan findings
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
// Submit: queue + flush
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
  queueEvent(event);

  if (shouldFlush()) {
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
  const batch = buildBatch();
  if (!batch) return true;

  const url = `${(registryUrl || REGISTRY_URL).replace(/\/+$/, '')}/api/v1/contribute`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `HackMyAgent-CLI/${VERSION}`,
      },
      body: JSON.stringify(batch),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (response.ok) {
      clearQueue();
      if (verbose) {
        process.stderr.write(
          `  Shared: anonymized results for ${batch.events.length} scan(s) (community trust)\n`,
        );
      }
      return true;
    }

    return false;
  } catch {
    // Offline or unreachable -- events stay in queue for next time
    return false;
  }
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
  queueEvent(payload);
  const ok = await flushQueue(registryUrl);
  return { success: ok };
}

/** @deprecated Kept for backward compat. */
export const generateContributorToken = getContributorToken;
