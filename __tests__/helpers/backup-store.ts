/**
 * Where a test finds the backups `--fix` wrote for a target (#376).
 *
 * `--fix` keeps them in the per-user backup store, outside the scanned tree,
 * in a directory keyed by the target's filesystem identity. vitest.setup.ts
 * points `HMA_BACKUP_HOME` at a directory of its own for every test file, so a
 * test reads the store its own runs wrote and nothing else. A spawned CLI sees
 * the same store when its environment spreads `process.env`.
 */
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { archiveStoreDirFor } from '../../src/store/archive-store';

/** The target's store directory, whether or not any run has created it yet. */
export async function storeDirOf(target: string): Promise<string> {
  return archiveStoreDirFor(target);
}

/** The run directories `--fix` created for `target`, oldest first; [] when there is no store. */
export async function storeRuns(target: string): Promise<string[]> {
  const dir = await storeDirOf(target);
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory() && !e.name.startsWith('.')).map((e) => e.name).sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}

/** The newest run directory for `target`, as an absolute path. Throws when there is none. */
export async function latestStoreRun(target: string): Promise<string> {
  const runs = await storeRuns(target);
  if (runs.length === 0) throw new Error(`no --fix backup in the store for ${target}`);
  return path.join(await storeDirOf(target), runs[runs.length - 1]);
}
