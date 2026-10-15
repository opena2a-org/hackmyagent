/**
 * Pending-scan queue for `check` command registry publishes (retry on failure).
 * Stored in ~/.opena2a/hma-pending-scans.json (separate from @opena2a/contribute queue).
 *
 * Each entry is the submission the failed publish sent: the scan's mapped
 * findings, its scan time and the version that scanned it. A retry sends
 * those. An entry an earlier version queued holds a finding count in place of
 * the findings and no scan time or tool version, so it is not sent again: the
 * registry reads an empty findings list as a scan with no findings.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join } from 'path';
import type { ScanFinding } from '@opena2a/registry-client';

export function getPendingScansPath(): string {
  const home = process.env.OPENA2A_HOME || join(homedir(), '.opena2a');
  return join(home, 'hma-pending-scans.json');
}

/** A queued publish: the fields of the submission `check` sent for the scan. */
export interface PendingScan {
  name: string;
  score: number;
  maxScore: number;
  projectType: string;
  toolVersion: string;
  scanTimestamp: string;
  findings: ScanFinding[];
}

/** The queued entries, or none when the file is missing, unreadable or not a JSON array. */
export function readPendingScans(p: string): unknown[] {
  try {
    const queue: unknown = JSON.parse(readFileSync(p, 'utf-8'));
    return Array.isArray(queue) ? queue : [];
  } catch {
    return [];
  }
}

const isText = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

function scanFinding(f: unknown): ScanFinding | null {
  if (typeof f !== 'object' || f === null) return null;
  const { checkId, name, severity, passed, message, category } = f as Record<string, unknown>;
  if (!isText(checkId) || typeof name !== 'string' || !isText(severity) || typeof passed !== 'boolean' || typeof message !== 'string') return null;
  if (category !== undefined && typeof category !== 'string') return null;
  return { checkId, name, severity, passed, message, ...(category !== undefined ? { category } : {}) };
}

/**
 * The entry as a submission to send again, holding only the submission's
 * fields, or null when any is missing or malformed. An entry an earlier
 * version queued is null: it has a finding count and a queue time, and no
 * findings, scan time or tool version.
 */
export function resendablePendingScan(entry: unknown): PendingScan | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const e = entry as Record<string, unknown>;
  if (!isText(e.name) || !isText(e.projectType) || !isText(e.toolVersion)) return null;
  if (typeof e.score !== 'number' || !Number.isFinite(e.score)) return null;
  if (typeof e.maxScore !== 'number' || !Number.isFinite(e.maxScore)) return null;
  if (!isText(e.scanTimestamp) || Number.isNaN(Date.parse(e.scanTimestamp))) return null;
  if (!Array.isArray(e.findings)) return null;
  const findings: ScanFinding[] = [];
  for (const f of e.findings) {
    const finding = scanFinding(f);
    if (!finding) return null;
    findings.push(finding);
  }
  return {
    name: e.name,
    score: e.score,
    maxScore: e.maxScore,
    projectType: e.projectType,
    toolVersion: e.toolVersion,
    scanTimestamp: e.scanTimestamp,
    findings,
  };
}

/**
 * Writes the queue readable and writable by its owner only (0600), as
 * writeConfig in opt-in.ts writes config.json. `mode` applies only when the
 * file is created, so the chmod narrows a queue an earlier version left at
 * 0644.
 */
export function writePendingScans(p: string, queue: unknown[]): void {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(queue, null, 2), { mode: 0o600 });
  try { chmodSync(p, 0o600); } catch { /* Windows: no mode bits */ }
}
