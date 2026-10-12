/**
 * #1051 — the backup store refuses what another user account created in it.
 *
 * The store is keyed by `<dev>-<ino>-<birth>`, three numbers any account can
 * read with `stat`. With `HMA_BACKUP_HOME` set to a directory other accounts
 * can write, one of them could create that key before this account's first
 * `--fix`, with no `target.json` and a run whose `.manifest.json` lists files
 * and modes. Measured before this was fixed: `findArchiveStore` reported such a
 * directory as the target's store, and `rollback` restored the planted copies
 * into the target. Nothing checked who owned the store directory, its
 * `target.json` or a run directory, and the store root's mode was never read.
 *
 * Another account cannot be created here, so the cells that need one make a
 * named path report another account's uid to `lstat` and `stat`. The ownership
 * is the only thing simulated; every file is real. The store root's mode is
 * real too: those cells `chmod` it.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { chmodSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { describeArchiveStore, findArchiveStore, prepareArchiveStore } from '../../src/store/archive-store';
import { tempDir } from '../helpers/temp-dir';
import { storeDirOf } from '../helpers/backup-store';

/** The paths that report another account's uid while a cell runs. */
const owners = vi.hoisted(() => ({ foreign: new Set<string>() }));

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  type StatFn = (p: unknown, opts?: { bigint?: boolean }) => Promise<{ uid: number | bigint }>;
  const otherOwner = (real: StatFn) => vi.fn(async (p: unknown, opts?: { bigint?: boolean }) => {
    const st = await real(p, opts);
    if (!owners.foreign.has(String(p))) return st;
    const uid = typeof st.uid === 'bigint' ? st.uid + 1n : st.uid + 1;
    return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid });
  });
  return {
    ...actual,
    lstat: otherOwner(actual.lstat as unknown as StatFn),
    stat: otherOwner(actual.stat as unknown as StatFn),
  };
});

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const PLANTED = '{"planted": true}\n';

function fixableTree(): string {
  const dir = tempDir('hma-1051-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`);
  return dir;
}

const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');

async function fix(target: string): Promise<string> {
  const before = liveConfig(target);
  await new HardeningScanner().scan({ targetDir: target, autoFix: true });
  expect(liveConfig(target), 'the fix did not redact the credential; this cell measures nothing').toContain('${GITHUB_TOKEN}');
  return before;
}

/** A run another account could write: a manifest listing `config.json` and a copy that says it was planted. */
function plantRun(store: string, name: string): string {
  const run = path.join(store, name);
  mkdirSync(run, { recursive: true });
  writeFileSync(path.join(run, '.manifest.json'), JSON.stringify({
    version: 1, existingFiles: ['config.json'], existingFileModes: { 'config.json': 0o644 }, absentAtBackup: [],
  }));
  writeFileSync(path.join(run, 'config.json'), PLANTED);
  return run;
}

/** The store root, created private, so only the ownership a cell names differs from a real store. */
function privateRoot(store: string): void {
  mkdirSync(path.dirname(store), { recursive: true });
  chmodSync(path.dirname(store), 0o700);
}

/** Every entry under `dir` with its bytes, so a later read proves nothing in it was moved, removed or rewritten. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (rel: string): void => {
    for (const e of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = path.join(rel, e.name);
      if (e.isDirectory()) { out[r + '/'] = ''; walk(r); } else out[r] = readFileSync(path.join(dir, r), 'utf-8');
    }
  };
  walk('');
  return out;
}

describe.skipIf(process.platform === 'win32')('#1051 a backup store another user account created is refused', () => {
  afterEach(() => {
    owners.foreign.clear();
  });

  it('rollback does not restore from a store directory with no target.json that another account created', async () => {
    const target = fixableTree();
    const before = liveConfig(target);
    const store = await storeDirOf(target);
    privateRoot(store);
    plantRun(store, '2026-01-01-000000-ABCDEF12');

    // Control: owned by this account, the same directory is this target's store.
    expect((await findArchiveStore(target)).kind, 'the planted store is not usable at all; this cell measures nothing').toBe('store');

    owners.foreign.add(store);
    const found = await findArchiveStore(target);
    expect(found.kind, 'a store directory another account created was taken as this target\'s store').toBe('unknown');
    expect(found.kind === 'unknown' ? found.reason : '').toMatch(/another user account/);
    expect(await describeArchiveStore(target), 'another account\'s runs were counted as this target\'s backups').toBeUndefined();
    await expect(new HardeningScanner().rollback(target)).rejects.toThrow(/another user account/);
    expect(liveConfig(target), 'rollback restored the planted copy into the target').toBe(before);
  }, 60_000);

  it('--fix detects only, and adopts nothing, when another account created the store directory', async () => {
    const target = fixableTree();
    const before = liveConfig(target);
    const store = await storeDirOf(target);
    privateRoot(store);
    plantRun(store, '2026-01-01-000000-ABCDEF12');
    const planted = snapshot(store);
    owners.foreign.add(store);

    await expect(prepareArchiveStore(target)).rejects.toMatchObject({ code: 'HMA-BACKUP-NOT-OWNED', path: store });

    const result = await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');
    expect(refused, '--fix wrote its backups into a store another account created').toHaveLength(1);
    expect(refused[0].message).toMatch(/another user account/);
    expect(refused[0].fix, 'the remedy does not name the override').toContain('HMA_BACKUP_HOME');
    expect(liveConfig(target), 'a fix landed with no backup this account owns').toBe(before);
    expect(snapshot(store), 'the other account\'s store was written to, moved or adopted').toEqual(planted);
  }, 60_000);

  it('refuses a target.json another account wrote, in rollback and in --fix, and moves nothing aside', async () => {
    const target = fixableTree();
    await fix(target);
    const fixed = liveConfig(target);
    const store = await storeDirOf(target);
    const record = path.join(store, 'target.json');
    owners.foreign.add(record);

    const found = await findArchiveStore(target);
    expect(found.kind, 'a target.json another account wrote decided whose store this is').toBe('unknown');
    expect(found.kind === 'unknown' ? found.reason : '').toMatch(/target\.json belongs to another user account/);
    await expect(new HardeningScanner().rollback(target)).rejects.toThrow(/another user account/);
    expect(liveConfig(target)).toBe(fixed);

    await expect(prepareArchiveStore(target)).rejects.toMatchObject({ code: 'HMA-BACKUP-NOT-OWNED', path: store });
    expect(
      readdirSync(path.dirname(store)).filter((n) => n.startsWith(`${path.basename(store)}.replaced-`)),
      'a store with another account\'s record was moved aside and replaced',
    ).toEqual([]);
  }, 120_000);

  it('rollback passes over a run directory another account created, names it, and restores this account\'s run', async () => {
    const target = fixableTree();
    const original = await fix(target);
    const store = await storeDirOf(target);
    // Sorts above every real stamp, so it is the first candidate rollback tries.
    const theirs = plantRun(store, '9999-12-31-235959-FFFFFFFF');
    owners.foreign.add(theirs);

    const report = await new HardeningScanner().rollback(target);

    expect(liveConfig(target), 'rollback restored the run another account created').toBe(original);
    expect(report.restored).toContain('config.json');
    expect(report.skippedBackups).toEqual([
      { name: path.basename(theirs), reason: expect.stringMatching(/another user account/) },
    ]);
    expect(readFileSync(path.join(theirs, 'config.json'), 'utf-8'), 'the passed-over run was changed or removed').toBe(PLANTED);
  }, 120_000);
});

describe.skipIf(process.platform === 'win32')('#1051 a store root other accounts can write needs the sticky bit', () => {
  let saved: string | undefined;

  beforeEach(() => {
    saved = process.env.HMA_BACKUP_HOME;
  });

  afterEach(() => {
    if (saved === undefined) delete process.env.HMA_BACKUP_HOME; else process.env.HMA_BACKUP_HOME = saved;
  });

  /** An existing `HMA_BACKUP_HOME` with the mode a cell names. */
  function namedRoot(mode: number, name = 'shared'): string {
    const root = path.join(tempDir('hma-1051-root-'), name);
    mkdirSync(root);
    chmodSync(root, mode);
    process.env.HMA_BACKUP_HOME = root;
    return root;
  }

  it.each(['777', '770', '703'])('--fix detects only under a root of mode %s, and writes nothing into it', async (octal) => {
    const rootMode = parseInt(octal, 8);
    const target = fixableTree();
    const before = liveConfig(target);
    const root = namedRoot(rootMode);

    await expect(prepareArchiveStore(target)).rejects.toMatchObject({ code: 'HMA-BACKUP-SHARED-ROOT' });

    const result = await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');
    expect(refused, '--fix stored backups in a root any account can replace entries of').toHaveLength(1);
    expect(refused[0].message).toMatch(/sticky bit/);
    expect(refused[0].fix).toContain('chmod');
    expect(refused[0].fix).toContain('HMA_BACKUP_HOME');
    expect(liveConfig(target)).toBe(before);
    expect(readdirSync(root), 'something was written into the shared root').toEqual([]);
    expect((statSync(root).mode & 0o7777).toString(8), 'the run changed the mode of a directory the user named').toBe(rootMode.toString(8));
  }, 60_000);

  /** The remedy `--fix` reports for a root of mode 777 with the name a cell gives it. */
  async function sharedRootRemedy(name: string): Promise<{ root: string; remedy: string }> {
    const target = fixableTree();
    const root = namedRoot(0o777, name);
    const result = await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');
    expect(refused, '--fix did not refuse the shared root; this cell measures nothing').toHaveLength(1);
    return { root, remedy: refused[0].fix ?? '' };
  }

  it('cites a root whose name needs quoting as one operand of the chmod it offers', async () => {
    const { root, remedy } = await sharedRootRemedy('shared root');
    // The store reports the root resolved, which is not the spelling `tempDir` returned.
    expect(remedy).toContain(`Run chmod go-w '${realpathSync(root)}', or set HMA_BACKUP_HOME`);
  }, 60_000);

  it('offers no chmod for a root whose name cannot be shown truthfully in a command', async () => {
    const { remedy } = await sharedRootRemedy('shared\nroot');
    expect(remedy).not.toContain('chmod');
    expect(remedy).toMatch(/^Set HMA_BACKUP_HOME to a directory only your account can write, then re-run: /);
  }, 60_000);

  it('rollback refuses a store whose root became writable by other accounts', async () => {
    const target = fixableTree();
    const root = namedRoot(0o700);
    await fix(target);
    const fixed = liveConfig(target);
    chmodSync(root, 0o777);

    const found = await findArchiveStore(target);
    expect(found.kind).toBe('unknown');
    expect(found.kind === 'unknown' ? found.reason : '').toMatch(/sticky bit/);
    await expect(new HardeningScanner().rollback(target)).rejects.toThrow(/sticky bit/);
    expect(liveConfig(target)).toBe(fixed);
  }, 120_000);

  it.each(['1777', '1770', '755'])('accepts a root of mode %s, and rollback restores from it', async (octal) => {
    const target = fixableTree();
    namedRoot(parseInt(octal, 8));
    const original = await fix(target);

    expect((await findArchiveStore(target)).kind).toBe('store');
    await new HardeningScanner().rollback(target);
    expect(liveConfig(target)).toBe(original);
  }, 120_000);
});
