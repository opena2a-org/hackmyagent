/**
 * NanoMind Classification Telemetry
 *
 * Posts anonymous classification stats to the Registry's NanoMind
 * telemetry endpoint. This feeds the intelligence loop: aggregated
 * stats show which content types and classifications are most common,
 * enabling targeted model improvements.
 *
 * Endpoint:  POST api.oa2a.org/api/v1/nanomind/telemetry
 *
 * PRIVACY: Only content type, content hash (SHA-256), classification,
 * confidence, verdict, and model version are sent. No file paths,
 * no source code, no raw content, no PII.
 *
 * Respects the same contribute.enabled opt-in as scan contributions.
 */

import { createHash } from 'node:crypto';
import { VERSION } from '../index.js';
import { isContributeEnabled } from './opt-in.js';

const REGISTRY_URL = 'https://api.oa2a.org';
const TELEMETRY_ENDPOINT = '/api/v1/nanomind/telemetry';
const SUBMIT_TIMEOUT_MS = 5000;
const MAX_BATCH_SIZE = 100;

export interface ClassificationStat {
  contentType: string;   // skill, soul, mcp_tool, system_prompt, etc.
  contentHash: string;   // SHA-256 of content (computed locally)
  classification: string; // benign, suspicious, malicious
  confidence: number;
  verdict: string;       // pass, warn, fail
  modelVersion: string;
}

// In-memory queue to batch telemetry submissions
let queue: ClassificationStat[] = [];

/**
 * Hash content for telemetry (privacy-preserving identifier).
 * Only the hash is sent, never the content itself.
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Derive verdict from classification + confidence.
 */
function deriveVerdict(classification: string, confidence: number): string {
  if (classification === 'malicious' && confidence > 0.7) return 'fail';
  if (classification === 'suspicious' || (classification === 'malicious' && confidence <= 0.7)) return 'warn';
  return 'pass';
}

/**
 * Queue a classification result for telemetry submission.
 * Call this after every NanoMind classification during a scan.
 */
export function queueClassificationStat(
  contentType: string,
  content: string,
  classification: string,
  confidence: number,
  modelVersion: string,
): void {
  if (!isContributeEnabled()) return;

  queue.push({
    contentType,
    contentHash: hashContent(content),
    classification,
    confidence,
    verdict: deriveVerdict(classification, confidence),
    modelVersion,
  });
}

/**
 * Submit queued telemetry to the Registry.
 * Call after scan completes. Non-blocking, best-effort.
 */
export async function flushNanoMindTelemetry(
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  if (queue.length === 0) return true;
  if (!isContributeEnabled()) {
    queue = [];
    return true;
  }

  const batch = queue.splice(0, MAX_BATCH_SIZE);
  const url = (registryUrl || REGISTRY_URL) + TELEMETRY_ENDPOINT;

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: `hackmyagent@${VERSION}`,
        stats: batch.map(s => ({
          contentType: s.contentType,
          contentHash: s.contentHash,
          classification: s.classification,
          confidence: s.confidence,
          verdict: s.verdict,
          modelVersion: s.modelVersion,
          timestamp: new Date().toISOString(),
        })),
      }),
      signal: AbortSignal.timeout(SUBMIT_TIMEOUT_MS),
    });

    if (verbose) {
      const body = await resp.json().catch(() => ({}));
      process.stderr.write(
        `NanoMind telemetry: ${resp.status} (${(body as Record<string, unknown>).accepted ?? 0}/${batch.length} accepted)\n`,
      );
    }

    return resp.ok;
  } catch {
    // Non-fatal: telemetry failure should never affect scan results
    if (verbose) {
      process.stderr.write('NanoMind telemetry: submission failed (network error)\n');
    }
    return false;
  }
}

/**
 * Get the current queue size (for testing/debugging).
 */
export function getTelemetryQueueSize(): number {
  return queue.length;
}

/**
 * Clear the queue without submitting (for testing).
 */
export function clearTelemetryQueue(): void {
  queue = [];
}
