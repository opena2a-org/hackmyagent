/**
 * #588 — a directory the walker cannot LIST is an unread input of the
 * directory kind.
 *
 * `chmod 000 <dir>` (or a directory under a non-searchable parent) rejects the
 * walker's `readdir`. Before this change the rejection was swallowed at the
 * discovery site and the coverage ledger recorded nothing: every path under
 * the directory left the scan without a single read ever being attempted, so
 * nothing on the read channel could disclose it. The only trace was the
 * sensitive-artifact walk's `walkComplete = false`, which reaches output only
 * through the GIT-001/GIT-002 severity escalation and never names the
 * directory.
 *
 * This layer is unconditional on purpose: the rejection is injected through the
 * tracked namespace, so it holds under root, where `chmod 000` denies nothing.
 * The end-to-end half (real mode-000 directories, exit codes, the finding text
 * on both arms) lives in `__tests__/repo/obstruction-disclosure.test.ts`.
 *
 * The injection replaces `fs.readdir` on the tracked namespace itself, so the
 * wrapper's own failure reporting is bypassed here by construction: what this
 * suite pins is that the DISCOVERY SITE records the loss — the site that knows
 * the directory was discovered rather than probed — independently of the
 * wrapper. The wrapper's channel is pinned in `tracked-fs-discipline`.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as path from 'node:path';
import * as os from 'node:os';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';

/** Which directory rejects `readdir`, and with what errno. `null` = control. */
const reject = vi.hoisted((): { dir: string | null; code: string } => ({ dir: null, code: 'EACCES' }));

vi.mock('../../src/hardening/tracked-fs', async () => {
  const actual = await vi.importActual<typeof import('../../src/hardening/tracked-fs')>(
    '../../src/hardening/tracked-fs',
  );
  const realReaddir = actual.fs.readdir;
  const readdir = async (target: unknown, ...rest: unknown[]) => {
    if (reject.dir && typeof target === 'string' && path.resolve(target) === reject.dir) {
      const err = new Error(`${reject.code}: permission denied, scandir '${target}'`) as NodeJS.ErrnoException;
      err.code = reject.code;
      err.syscall = 'scandir';
      err.path = target;
      throw err;
    }
    return (realReaddir as (...a: unknown[]) => Promise<unknown>)(target, ...rest);
  };
  return { ...actual, fs: { ...actual.fs, readdir } };
});

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { CoverageLedger, withActiveLedger } from '../../src/hardening/coverage-ledger';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'hma-588-'));
  await mkdir(path.join(dir, 'cfg'));
  await writeFile(path.join(dir, 'util.js'), 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n');
  await writeFile(path.join(dir, 'cfg', 'secrets.js'), 'const K = process.env.API_KEY;\nmodule.exports = { K };\n');
  reject.dir = null;
  reject.code = 'EACCES';
});

afterEach(async () => {
  reject.dir = null;
  await rm(dir, { recursive: true, force: true });
});

async function scanWithLedger(): Promise<{ ledger: CoverageLedger; compiled: number }> {
  const ledger = new CoverageLedger(dir);
  const result = await withActiveLedger(ledger, () => runNanoMindScan(dir, [], 'library'));
  return { ledger, compiled: result.compiledArtifacts };
}

describe('the tracked wrapper itself records a rejected listing against the path that failed', () => {
  // No mock here: this drives the REAL tracked namespace, so it pins the
  // wrapper's own failure channel — including that a recursive readdir, which
  // Node rejects with the errno of a NESTED directory, is recorded against
  // that nested directory and never against its listable argument. The
  // assembly scanner lists `src/` recursively at standard depth; attributing
  // its rejection to `src/` named a directory that lists fine, printed a
  // remedy that is a no-op, and let coalescing suppress the true record.
  it('a recursive readdir rejected by a nested directory records the nested directory', async (ctx) => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'hma-588-wrap-'));
    try {
      await mkdir(path.join(dir, 'src', 'hidden'), { recursive: true });
      await writeFile(path.join(dir, 'src', 'a.ts'), 'export const x = 1;\n');
      const { chmod } = await import('node:fs/promises');
      await chmod(path.join(dir, 'src', 'hidden'), 0o000);
      let denied = false;
      try { await (await import('node:fs/promises')).readdir(path.join(dir, 'src', 'hidden')); } catch { denied = true; }
      if (!denied) {
        console.warn('[discover-directory] cannot deny listing to this process (root?): SKIPPING, not passing');
        await chmod(path.join(dir, 'src', 'hidden'), 0o755);
        ctx.skip();
      }
      const { fs: tracked } = await vi.importActual<typeof import('../../src/hardening/tracked-fs')>('../../src/hardening/tracked-fs');
      const ledger = new CoverageLedger(dir);
      await withActiveLedger(ledger, async () => {
        try { await tracked.readdir(path.join(dir, 'src'), { recursive: true }); } catch { /* the rejection under test */ }
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      expect(ledger.unreadablePaths()).toEqual([
        { path: path.join(dir, 'src', 'hidden'), code: 'EACCES', kind: 'directory' },
      ]);
      await chmod(path.join(dir, 'src', 'hidden'), 0o755);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe('#588 a directory whose readdir rejects is an unread input of the directory kind', () => {
  it('control: with readdir working, nothing is unread and cfg/secrets.js compiles', async () => {
    const { ledger, compiled } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    expect(compiled).toBeGreaterThanOrEqual(2);
  });

  it('records EACCES on a listed directory as one unread input, counted under directories', async () => {
    reject.dir = path.resolve(dir, 'cfg');
    const { ledger, compiled } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
    expect(ledger.unreadablePaths()).toEqual([
      { path: path.resolve(dir, 'cfg'), code: 'EACCES', kind: 'directory' },
    ]);
    // The readable half still compiles; the record does not pretend the
    // directory's contents were read.
    expect(compiled).toBeGreaterThanOrEqual(1);
  });

  it('EPERM is recorded too — the ledger admits every code it did not name as "not there"', async () => {
    reject.dir = path.resolve(dir, 'cfg');
    reject.code = 'EPERM';
    const { ledger } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EPERM: 1 }, directories: 1 });
  });

  it('ENOENT on a listed directory is NOT a lost input — removed between the listing and the walk', async () => {
    reject.dir = path.resolve(dir, 'cfg');
    reject.code = 'ENOENT';
    const { ledger } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  });

  it('the scan ROOT rejecting readdir is one lost directory, not silence', async () => {
    reject.dir = path.resolve(dir);
    const { ledger, compiled } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
    expect(ledger.unreadablePaths()).toEqual([{ path: path.resolve(dir), code: 'EACCES', kind: 'directory' }]);
    expect(compiled).toBe(0);
  });
});
