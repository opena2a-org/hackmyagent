/**
 * #516 — turning the semantic analyzer off (`--static-only`) must not turn its
 * discovery off.
 *
 * At `--scan-depth quick` this layer is the only component that discovers and
 * opens a source file. With `staticOnly` the orchestrator returned before
 * anything had walked the tree, so a discovered file it could not open left no
 * record on the coverage ledger, and `secure --static-only --scan-depth quick`
 * scored a tree holding a mode-000 file 98/100 at exit 0.
 *
 * The rejection is injected through the tracked `fs` namespace, so this holds
 * under root (where `chmod` denies nothing). The end-to-end matrix lives in
 * `__tests__/cli/secure-static-only-unread-gate.test.ts` and skips when the OS
 * declines to deny.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as path from 'node:path';
import * as os from 'node:os';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';

/** Which file rejects `open` and `readFile`, and with what errno. `null` = the real calls run. */
const reject = vi.hoisted((): { file: string | null; code: string } => ({ file: null, code: 'EACCES' }));

vi.mock('../../src/hardening/tracked-fs', async () => {
  const actual = await vi.importActual<typeof import('../../src/hardening/tracked-fs')>(
    '../../src/hardening/tracked-fs',
  );
  const denied = (call: string, target: unknown): NodeJS.ErrnoException | null => {
    if (!reject.file || target !== reject.file) return null;
    const err = new Error(`${reject.code}: permission denied, ${call} '${target}'`) as NodeJS.ErrnoException;
    err.code = reject.code;
    err.syscall = call;
    err.path = target as string;
    return err;
  };
  const { noteReadFailure } = await vi.importActual<typeof import('../../src/hardening/coverage-ledger')>(
    '../../src/hardening/coverage-ledger',
  );
  const realOpen = actual.fs.open as (...a: unknown[]) => Promise<unknown>;
  const realReadFile = actual.fs.readFile as (...a: unknown[]) => Promise<unknown>;
  const open = async (target: unknown, ...rest: unknown[]) => {
    const err = denied('open', target);
    if (err) throw err;
    return realOpen(target, ...rest);
  };
  // The compile loop reads through the tracked namespace, whose wrapper records
  // a rejection on the ledger. Reproduced here so the run with the analyzer on
  // records the injected loss the way the real namespace would.
  const readFile = async (target: unknown, ...rest: unknown[]) => {
    const err = denied('open', target);
    if (err) {
      noteReadFailure(target, err.code);
      throw err;
    }
    return realReadFile(target, ...rest);
  };
  return { ...actual, fs: { ...actual.fs, open, readFile } };
});

import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { CoverageLedger, withActiveLedger } from '../../src/hardening/coverage-ledger';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'hma-516-'));
  await mkdir(path.join(dir, 'src'));
  await writeFile(path.join(dir, 'src', 'util.js'), 'export function add(a, b) {\n  return a + b;\n}\n');
  await writeFile(path.join(dir, 'src', 'greet.js'), 'export function greet(name) {\n  return "Hello, " + name;\n}\n');
  reject.file = null;
  reject.code = 'EACCES';
});

afterEach(async () => {
  reject.file = null;
  await rm(dir, { recursive: true, force: true });
});

async function staticOnlyLedger(): Promise<{ ledger: CoverageLedger; compiled: number; nanomindUsed: boolean }> {
  const ledger = new CoverageLedger(dir);
  const result = await withActiveLedger(ledger, () =>
    orchestrateNanoMind(dir, [], { staticOnly: true, silent: true, projectType: 'library' }),
  );
  return { ledger, compiled: result.compiledArtifacts, nanomindUsed: result.nanomindUsed };
}

describe('#516 --static-only still records a discovered input it could not open', () => {
  it('control: with every file readable, nothing is unread', async () => {
    const { ledger } = await staticOnlyLedger();
    expect(ledger.unreadableInputs).toBeDefined();
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  });

  it('records EACCES on a discovered source file as one unread input', async () => {
    reject.file = path.join(dir, 'src', 'greet.js');
    const { ledger, compiled, nanomindUsed } = await staticOnlyLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });
    expect(ledger.unreadablePaths()).toEqual([
      { path: path.resolve(dir, 'src', 'greet.js'), code: 'EACCES', kind: 'file' },
    ]);
    // Discovery only: the analyzer stays off and contributes no coverage.
    expect(compiled).toBe(0);
    expect(nanomindUsed).toBe(false);
  });

  it('ENOENT is not a lost input: a file removed between the listing and the open', async () => {
    reject.file = path.join(dir, 'src', 'greet.js');
    reject.code = 'ENOENT';
    const { ledger } = await staticOnlyLedger();
    expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  });

  it('reports the same unread inputs as the run with the analyzer on', async () => {
    reject.file = path.join(dir, 'src', 'greet.js');
    const withAnalyzer = new CoverageLedger(dir);
    await withActiveLedger(withAnalyzer, () => runNanoMindScan(dir, [], 'library'));
    const { ledger: staticOnly } = await staticOnlyLedger();
    expect(withAnalyzer.unreadablePaths().length).toBe(1);
    expect(staticOnly.unreadablePaths()).toEqual(withAnalyzer.unreadablePaths());
  });
});
