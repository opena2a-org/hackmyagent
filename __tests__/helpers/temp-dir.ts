/**
 * The one way a test in this suite makes a temporary directory.
 *
 * Spawn tests give the CLI a throwaway HOME, and most wrote it inline:
 *
 *     env: { ...process.env, HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) }
 *
 * Nothing holds that path, so nothing can remove it. Two CLI test files, run
 * once with an empty TMPDIR, left 28 directories behind; a host that ran the
 * suite repeatedly collected more than sixteen thousand and filled its disk.
 *
 * `tempDir` creates the directory and registers its removal in the same call,
 * so a caller cannot get one without the other:
 *
 *   - created while a test is running (the test body, a `beforeEach`, or a
 *     helper either of them calls): removed when that test finishes, pass or
 *     fail, through `onTestFinished`;
 *   - created anywhere else (module scope, a `describe` body, `beforeAll`):
 *     removed when the file finishes, by the `afterAll` that vitest.setup.ts
 *     registers for every test file.
 *
 * The file-level pass also sweeps every directory the per-test pass missed: a
 * test cancelled with `ctx.skip()` never runs its `onTestFinished` callbacks,
 * and a fixture a test left unreadable cannot be removed until the file's own
 * `afterAll` restores its mode. Setup-file hooks are registered first and
 * after-hooks run in reverse, so this pass runs after the file's own.
 *
 * A directory that still cannot be removed at the end of the file fails that
 * file's `afterAll`. Staying silent is how the leak grew unnoticed.
 *
 * Inside `test.concurrent` the running test is ambiguous; such a test should
 * create its directories in a hook instead. No concurrent test calls this.
 *
 * Contract pinned by __tests__/harness/temp-dir-cleanup.test.ts, which also
 * fails any test file that calls `mkdtemp` or `mkdtempSync` itself.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { onTestFinished } from 'vitest';

const pending = new Set<string>();

/**
 * A new, empty directory named `<parent>/<prefix>XXXXXX`, removed when the
 * test (or, outside a test, the file) that created it finishes. `parent`
 * defaults to the OS temporary directory; the return value is the path as
 * `mkdtempSync` reports it, not its realpath.
 */
export function tempDir(prefix: string, parent: string = os.tmpdir()): string {
  const dir = fs.mkdtempSync(path.join(parent, prefix));
  pending.add(dir);
  try {
    onTestFinished(() => {
      // A failure here is left for the file-level pass, which can still
      // succeed once the file's own `afterAll` has restored a mode.
      if (tryRemove(dir)) pending.delete(dir);
    });
  } catch {
    // Not inside a running test: the file-level pass owns it.
  }
  return dir;
}

/** Removes every directory still pending. Called from vitest.setup.ts. */
export function removeTempDirs(): void {
  const failed: string[] = [];
  for (const dir of pending) {
    if (tryRemove(dir)) pending.delete(dir);
    else failed.push(dir);
  }
  if (failed.length > 0) {
    throw new Error(`tempDir could not remove ${failed.length} director${failed.length === 1 ? 'y' : 'ies'}: ${failed.join(', ')}`);
  }
}

function tryRemove(dir: string): boolean {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
    return true;
  } catch {
    // Fixtures for unreadable-input tests chmod entries to 000, which a
    // recursive remove cannot list. Give the owner access back and retry.
    restoreOwnerAccess(dir);
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return true;
    } catch {
      return false;
    }
  }
}

function restoreOwnerAccess(p: string): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(p);
  } catch {
    return;
  }
  if (st.isSymbolicLink()) return;
  try {
    fs.chmodSync(p, st.isDirectory() ? 0o700 : 0o600);
  } catch {
    return;
  }
  if (!st.isDirectory()) return;
  let entries: string[];
  try {
    entries = fs.readdirSync(p);
  } catch {
    return;
  }
  for (const entry of entries) restoreOwnerAccess(path.join(p, entry));
}
