/**
 * #1049: a directory whose reported birth time changes after `secure --fix`
 * still has its backups named by `rollback`.
 *
 * The backup store is keyed `<dev>-<ino>-<birth>`, so that a directory which
 * takes a removed directory's inode number gets a store of its own. The birth
 * time a filesystem reports can change, though. On macOS (APFS) it moves back
 * when the directory's modification time is set earlier, as `touch -t`,
 * `rsync -a`, `tar -x` and `cp -p` do; where Node has no `statx` it reports the
 * change time, which moves forward when an entry is created or removed in the
 * directory. The directory's key then named no store. Measured on macOS with
 * `touch -t 200001010000 <dir>` after a `--fix`: `rollback` restored an older
 * archive from inside the tree, exited 0 with "Rollback complete", and said
 * "the backup store held none for it" while the store held the run just taken;
 * with no archive in the tree it exited 1 with "No backup found".
 *
 * `rollback` now looks for stores under the directory's device and inode
 * number and another birth time, names them, and never restores from them. A
 * directory that reports an earlier birth time than such a store's key cannot
 * be a later directory that took a removed one's inode number, so that store
 * is its own: nothing is restored, from the store or from the tree. Otherwise
 * the archive in the tree is used as before and the report names the store.
 *
 * The in-process cells change one thing: the birth time the bigint `stat` of
 * the target reports. The spawned cells cannot reach into the child, so they
 * move the store to the key another birth time gives, which is the same
 * relation between key and directory seen from the store.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { findArchiveStore, findOtherBirthStores } from '../../src/store/archive-store';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { storeDirOf, storeRuns } from '../helpers/backup-store';

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

/** The directory whose bigint `stat` reports another birth time, while a cell runs. */
const changed = vi.hoisted(() => ({
  current: undefined as { real: string; birthtimeNs: bigint } | undefined,
}));

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  const realStat = actual.stat as (p: unknown, opts?: { bigint?: boolean }) => Promise<object>;
  return {
    ...actual,
    stat: vi.fn(async (p: unknown, opts?: { bigint?: boolean }) => {
      const st = await realStat(p, opts);
      const c = changed.current;
      if (!c || !opts?.bigint || String(p) !== c.real) return st;
      return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { birthtimeNs: c.birthtimeNs });
    }),
  };
});

/** Assembled at run time, so no credential-shaped literal is in the source tree. */
const FAKE_GH_TOKEN = ['gh', 'p_', 'a'.repeat(36)].join('');

const HOUR_NS = 3_600_000_000_000n;
/** 2000-01-01T00:00:00Z, the birth time `touch -t 200001010000` leaves on APFS (in UTC). */
const YEAR_2000_NS = 946_684_800_000_000_000n;

const configJson = (port: number): string => `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port }, null, 2)}\n`;
const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');
const realDir = (dir: string): string => realpathSync.native(dir);

/** A tree `--fix` changes: the token in `config.json` is replaced by a reference. */
function fixableTree(port: number): string {
  const dir = tempDir('hma-1049-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), configJson(port));
  return dir;
}

/** Fix `target` and return its store, which then holds one run with the pre-fix `config.json`. */
async function fixed(target: string): Promise<string> {
  await new HardeningScanner().scan({ targetDir: target, autoFix: true });
  expect(liveConfig(target), 'the fix did not redact the credential; this cell measures nothing').toContain('${GITHUB_TOKEN}');
  expect(await storeRuns(target), 'the fix left no run in the store; this cell measures nothing').toHaveLength(1);
  return storeDirOf(target);
}

/** The archive an earlier version left inside the tree: an older `config.json`, with port 1111. */
function plantInTreeArchive(target: string): string {
  const run = path.join(target, '.hackmyagent-backup', '2026-01-01T00-00-00-000Z');
  mkdirSync(run, { recursive: true });
  writeFileSync(path.join(run, 'config.json'), configJson(1111));
  writeFileSync(
    path.join(run, '.manifest.json'),
    `${JSON.stringify({ version: 2, existingFiles: ['config.json'], absentAtBackup: [], createdFiles: [] })}\n`,
  );
  return run;
}

/** From here the target reports `birthtimeNs` (or its own birth time moved by `byNs`) to the store. */
function reportBirth(target: string, to: { at?: bigint; byNs?: bigint }): void {
  const real = realDir(target);
  const own = statSync(real, { bigint: true }).birthtimeNs;
  changed.current = { real, birthtimeNs: to.at ?? own + (to.byNs ?? 0n) };
}

/** The error `rollback` ends with, or a failure when it restored. */
async function rollbackError(target: string): Promise<string> {
  try {
    await new HardeningScanner().rollback(target);
  } catch (err) {
    return (err as Error).message;
  }
  throw new Error('rollback reported a restore where it had to refuse');
}

describe('#1049 a directory whose reported birth time moved back keeps its backups in view', () => {
  afterEach(() => {
    changed.current = undefined;
  });

  it.each([
    { tree: 'an older archive inside the tree', inTree: true },
    { tree: 'no archive inside the tree', inTree: false },
  ])('names the store and restores nothing, with $tree', async ({ inTree }) => {
    const target = fixableTree(2222);
    const store = await fixed(target);
    const afterFix = liveConfig(target);
    const archive = inTree ? plantInTreeArchive(target) : undefined;

    reportBirth(target, { at: YEAR_2000_NS });
    expect((await findArchiveStore(target)).kind, 'the changed birth time still names the store; this cell measures nothing')
      .toBe('none');

    const said = await rollbackError(target);

    expect(said, 'the refusal does not name the store that holds the backups').toContain(store);
    expect(said).toContain(`(last seen at ${realDir(target)})`);
    expect(said).toContain('restored nothing');
    expect(said, 'a directory with backups in the store was told it has none').not.toContain('No backup found');
    expect(liveConfig(target), 'a refused rollback changed the live file').toBe(afterFix);
    if (archive) expect(existsSync(archive), 'a refused rollback consumed the archive inside the tree').toBe(true);

    changed.current = undefined;
    expect(await storeRuns(target), 'the store lost its run').toHaveLength(1);
  }, 120_000);

  it('is not hidden by an empty store under the key the directory has now', async () => {
    const target = fixableTree(2222);
    const store = await fixed(target);
    plantInTreeArchive(target);

    reportBirth(target, { at: YEAR_2000_NS });
    // What a later `--fix` that backed up nothing, or a rollback that consumed
    // its only run, leaves under the new key.
    mkdirSync(await storeDirOf(target), { recursive: true });
    expect((await findArchiveStore(target)).kind).toBe('store');

    const said = await rollbackError(target);

    expect(said).toContain(store);
    expect(liveConfig(target), 'the older archive inside the tree was restored').not.toContain('1111');
  }, 120_000);
});

describe('#1049 a later birth time does not tell a changed one from a reused inode number', () => {
  afterEach(() => {
    changed.current = undefined;
  });

  it.each([
    { tree: 'no archive inside the tree', emptyArchive: false },
    { tree: 'a .hackmyagent-backup inside the tree that holds no run', emptyArchive: true },
  ])('says no backup was found and names the store, with $tree', async ({ emptyArchive }) => {
    const target = fixableTree(2222);
    const store = await fixed(target);
    const afterFix = liveConfig(target);
    if (emptyArchive) mkdirSync(path.join(target, '.hackmyagent-backup'));

    reportBirth(target, { byNs: HOUR_NS });
    const said = await rollbackError(target);

    expect(said).toMatch(/^No backup found\./);
    expect(said, 'the store that may hold this directory\'s backups is not named').toContain(store);
    expect(said).toContain('was not used');
    // A `--fix` run now would back up the files as the earlier run left them.
    expect(said, 'a directory whose backups may be in the named store was told to run --fix first')
      .not.toContain('secure --fix');
    expect(liveConfig(target)).toBe(afterFix);
  }, 120_000);

  it('restores the archive inside the tree and reports the store it did not use', async () => {
    const target = fixableTree(2222);
    const store = await fixed(target);
    plantInTreeArchive(target);

    reportBirth(target, { byNs: HOUR_NS });
    const report = await new HardeningScanner().rollback(target);

    expect(report.backupSource).toBe('in-tree');
    expect(liveConfig(target)).toBe(configJson(1111));
    expect(report.otherBirthStores, 'the report does not carry the store that was passed over')
      .toContainEqual({ dir: store, lastKnownPath: realDir(target) });

    changed.current = undefined;
    expect(await storeRuns(target), 'a store that was not used lost its run').toHaveLength(1);
  }, 120_000);

  it('reports no such store when the directory restores from an archive inside the tree and has none', async () => {
    const target = fixableTree(2222);
    plantInTreeArchive(target);

    const report = await new HardeningScanner().rollback(target);

    expect(report.backupSource).toBe('in-tree');
    expect((report.otherBirthStores ?? []).filter((s) => s.lastKnownPath === realDir(target))).toEqual([]);
  }, 120_000);
});

describe('#1049 which stores count as kept under another birth time', () => {
  it('lists a store with a run, by its key, and leaves out an empty one and one moved aside', async () => {
    const target = fixableTree(2222);
    const id = statSync(realDir(target), { bigint: true });
    const root = path.dirname(await storeDirOf(target));
    const keyed = (birth: bigint, suffix = ''): string => path.join(root, `${id.dev}-${id.ino}-${birth}${suffix}`);

    const later = keyed(id.birthtimeNs + HOUR_NS);
    const earlier = keyed(id.birthtimeNs - HOUR_NS);
    const empty = keyed(id.birthtimeNs + 2n * HOUR_NS);
    const aside = keyed(id.birthtimeNs + 3n * HOUR_NS, '.replaced-1-abcd1234');
    const otherInode = path.join(root, `${id.dev}-${id.ino}0-${id.birthtimeNs + HOUR_NS}`);
    for (const dir of [later, earlier, aside, otherInode]) mkdirSync(path.join(dir, 'run'), { recursive: true });
    mkdirSync(empty, { recursive: true });

    const found = await findOtherBirthStores(target);

    expect(found.kind).toBe('listed');
    const stores = found.kind === 'listed' ? found.stores : [];
    expect(stores.find((s) => s.dir === later), 'a store keyed by a later birth time is not listed')
      .toEqual({ dir: later, lastKnownPath: undefined, targetBornEarlier: true });
    expect(stores.find((s) => s.dir === earlier), 'a store keyed by an earlier birth time is not listed')
      .toEqual({ dir: earlier, lastKnownPath: undefined, targetBornEarlier: false });
    const listed = stores.map((s) => s.dir);
    expect(listed, 'a store with no run was listed').not.toContain(empty);
    expect(listed, 'a store moved aside was listed').not.toContain(aside);
    expect(listed, 'another inode number\'s store was listed').not.toContain(otherInode);
  });

  it('lists nothing for a directory whose only store is under its own key', async () => {
    const target = fixableTree(2222);
    const store = await fixed(target);

    const found = await findOtherBirthStores(target);

    expect(found.kind).toBe('listed');
    expect(found.kind === 'listed' ? found.stores.map((s) => s.dir) : [], 'a directory\'s own store was listed as another\'s')
      .not.toContain(store);
  }, 120_000);
});

describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
  '#1049 a store root that cannot be listed',
  () => {
    it('is not read as a store that holds nothing: rollback refuses and leaves the archive inside the tree', async () => {
      const target = fixableTree(2222);
      const archive = plantInTreeArchive(target);
      const root = tempDir('hma-1049-root-');
      const saved = process.env.HMA_BACKUP_HOME;
      process.env.HMA_BACKUP_HOME = root;
      // Searchable and not readable: the directory's own key can be looked up
      // and is absent, and the stores beside it cannot be listed.
      chmodSync(root, 0o300);
      try {
        const said = await rollbackError(target);

        expect(said).toContain(realDir(root));
        expect(said).toContain('could not be listed');
        expect(said).toContain('Nothing was restored');
        expect(liveConfig(target), 'the archive inside the tree was restored').toBe(configJson(2222));
        expect(existsSync(archive)).toBe(true);
      } finally {
        chmodSync(root, 0o700);
        if (saved === undefined) delete process.env.HMA_BACKUP_HOME; else process.env.HMA_BACKUP_HOME = saved;
      }
    });
  },
);

describe('#1049 the rollback command says which store it did not use', () => {
  beforeAll(assertDistFresh);

  interface Spawned { stdout: string; stderr: string; status: number | null }

  /** The built CLI, with the backup store this file's own runs wrote to. */
  function hma(args: string[]): Spawned {
    const res = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { stdout: res.stdout ?? '', stderr: res.stderr ?? '', status: res.status };
  }

  /**
   * Move `target`'s store to the key a birth time `byNs` away gives, record
   * included, and return where it is now. To the store this is the directory
   * reporting another birth time than when the run was taken.
   */
  async function rekeyStore(target: string, byNs: bigint): Promise<string> {
    const from = await storeDirOf(target);
    const id = statSync(realDir(target), { bigint: true });
    const birth = id.birthtimeNs + byNs;
    const to = path.join(path.dirname(from), `${id.dev}-${id.ino}-${birth}`);
    renameSync(from, to);
    const recordFile = path.join(to, 'target.json');
    const record = JSON.parse(readFileSync(recordFile, 'utf-8')) as Record<string, unknown>;
    writeFileSync(recordFile, `${JSON.stringify({ ...record, birthtimeNs: birth.toString() }, null, 2)}\n`);
    return to;
  }

  it('exits 1, names the store and restores nothing when the directory reports the earlier birth time', async () => {
    const target = fixableTree(2222);
    await fixed(target);
    const afterFix = liveConfig(target);
    plantInTreeArchive(target);
    const store = await rekeyStore(target, HOUR_NS);

    const run = hma(['rollback', target]);

    expect(run.status, 'rollback reported success with this directory\'s newer backups unused').toBe(1);
    expect(run.stderr).toContain('Error: This directory\'s backups are in the backup store');
    expect(run.stderr).toContain(store);
    expect(run.stdout).not.toContain('Rollback complete');
    expect(liveConfig(target), 'the older archive inside the tree was restored').toBe(afterFix);
  }, 120_000);

  it('restores the archive inside the tree, names the store, and does not say the store held none', async () => {
    const target = fixableTree(2222);
    await fixed(target);
    plantInTreeArchive(target);
    const store = await rekeyStore(target, -HOUR_NS);

    const run = hma(['rollback', target]);

    expect(run.status).toBe(0);
    expect(run.stdout).toContain('Rollback complete');
    expect(liveConfig(target)).toBe(configJson(1111));
    expect(run.stdout, 'the report does not name the store it passed over')
      .toContain(`not used  ${store} (last seen at ${realDir(target)})`);
    expect(run.stdout).toContain('kept under another creation time');
    expect(run.stdout, 'the report says the store held no backup while it names one').not.toContain('held none for it');
  }, 120_000);
});
