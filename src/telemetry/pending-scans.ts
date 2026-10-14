/**
 * Pending-scan queue for `check` command registry publishes (retry on failure).
 * Stored in ~/.opena2a/hma-pending-scans.json (separate from @opena2a/contribute queue).
 */

import { chmodSync, mkdirSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join } from 'path';

export function getPendingScansPath(): string {
  const home = process.env.OPENA2A_HOME || join(homedir(), '.opena2a');
  return join(home, 'hma-pending-scans.json');
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
