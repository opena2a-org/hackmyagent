/**
 * #515 — a file the semantic walker DISCOVERED (its directory listing named it)
 * and then dropped because `stat` rejected is an input discovered but not read,
 * and must reach the coverage ledger's failure channel.
 *
 * Measured on `0e0cecf`: `chmod 600 cfg/` (readable, not traversable) leaves
 * `readdir` listing `cfg/secrets.js` while `stat` on it rejects `EACCES`. The
 * walker's size gate returned `false` and the discovered file left the scan with
 * no record. At `--scan-depth quick`, where this walker is the only reader of
 * the tree, the tree scored 98/100 at exit 0; the same tree with `cfg/`
 * traversable scored 69/100 at exit 1. The score went UP because a discovered
 * credential file left the assessment — #438's shape through a different errno
 * path than the `chmod 000 <file>` case #499 closed.
 *
 * This layer is unconditional on purpose: the rejection is injected through the
 * tracked `fs` namespace, so it holds under root (where `chmod` denies nothing)
 * and pins the ledger contract regardless of who runs it. The end-to-end half —
 * a real mode-600 directory, exit codes, the `SCAN-UNREAD-001` finding — lives in
 * `__tests__/cli/secure-unread-directory-gate.test.ts` and skips when the OS
 * declines to deny.
 *
 * The walker runs OUTSIDE any `coverage.run()` frame, so the record lands under
 * `(unattributed)` — the failure channel's documented asymmetry (a failure is
 * recorded whoever raised it; an unattributable success is dropped).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as path from 'node:path';
import * as os from 'node:os';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';

/**
 * Which directory's children reject `stat`, and with what errno. Mutated per
 * test; `null` means the real `stat` runs untouched (the control).
 */
const reject = vi.hoisted((): { under: string | null; code: string } => ({ under: null, code: 'EACCES' }));

vi.mock('../../src/hardening/tracked-fs', async () => {
  const actual = await vi.importActual<typeof import('../../src/hardening/tracked-fs')>(
    '../../src/hardening/tracked-fs',
  );
  const realStat = actual.fs.stat;
  const stat = async (target: unknown, ...rest: unknown[]) => {
    if (
      reject.under &&
      typeof target === 'string' &&
      target.startsWith(reject.under + path.sep)
    ) {
      const err = new Error(`${reject.code}: permission denied, stat '${target}'`) as NodeJS.ErrnoException;
      err.code = reject.code;
      err.syscall = 'stat';
      err.path = target;
      throw err;
    }
    return (realStat as (...a: unknown[]) => Promise<unknown>)(target, ...rest);
  };
  return { ...actual, fs: { ...actual.fs, stat } };
});

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { CoverageLedger, withActiveLedger } from '../../src/hardening/coverage-ledger';

let dir: string;

/**
 * A benign readable half and one JS file inside `cfg/`. The content of the
 * dropped file is irrelevant to the ledger — the record is about the read that
 * never happened — but it is a compile candidate (`.js` is in the walker's
 * extension set), so in the control it is compiled and in the failure case it
 * is the file that leaves.
 */
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'hma-515-'));
  await mkdir(path.join(dir, 'cfg'));
  await writeFile(path.join(dir, 'util.js'), 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n');
  await writeFile(path.join(dir, 'cfg', 'secrets.js'), 'const K = process.env.API_KEY;\nmodule.exports = { K };\n');
  reject.under = null;
  reject.code = 'EACCES';
});

afterEach(async () => {
  reject.under = null;
  await rm(dir, { recursive: true, force: true });
});

async function scanWithLedger(): Promise<{ ledger: CoverageLedger; compiled: number }> {
  const ledger = new CoverageLedger(dir);
  const result = await withActiveLedger(ledger, () => runNanoMindScan(dir, [], 'library'));
  return { ledger, compiled: result.compiledArtifacts };
}

describe('#515 discovered file whose stat rejects is an unread input', () => {
  it('control: with stat working, nothing is unread and cfg/secrets.js compiles', async () => {
    const { ledger, compiled } = await scanWithLedger();
    // Presence first, then content: `expect(x?.count)` would pass against a
    // ledger that lost the field.
    expect(ledger.unreadableInputs).toBeDefined();
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {} });
    expect(compiled).toBeGreaterThanOrEqual(2);
  });

  it('records EACCES on a listed child as one unread input, on the readFile channel', async () => {
    reject.under = path.join(dir, 'cfg');
    const { ledger, compiled } = await scanWithLedger();

    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 } });
    expect(ledger.unreadablePaths()).toEqual([
      { path: path.resolve(dir, 'cfg', 'secrets.js'), code: 'EACCES' },
    ]);
    // The readable half is still analyzed: recording the loss must not blank
    // the run (the #438 "withholding" alternative was rejected for that).
    expect(compiled).toBeGreaterThanOrEqual(1);
  });

  it('EPERM is recorded too — the ledger admits every code it did not name as "not there"', async () => {
    reject.under = path.join(dir, 'cfg');
    reject.code = 'EPERM';
    const { ledger } = await scanWithLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EPERM: 1 } });
  });

  it('ENOENT on a listed child is NOT a lost input — a file removed between the listing and the stat', async () => {
    reject.under = path.join(dir, 'cfg');
    reject.code = 'ENOENT';
    const { ledger } = await scanWithLedger();
    // The record is made and the ledger's errno discrimination drops it — the
    // same rule `readFile` failures already follow, not a second one.
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {} });
    expect(ledger.unreadablePaths()).toEqual([]);
  });
});
