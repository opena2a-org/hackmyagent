/**
 * #376 — a directory that takes a removed directory's inode number gets a
 * backup store of its own.
 *
 * The store is keyed by the target's filesystem identity, so that a moved or
 * renamed directory keeps its backups. A device and an inode number alone are
 * not an identity: Linux filesystems give a removed directory's inode number
 * to the next directory created. Measured on ext4, the next directory took the
 * removed one's inode number in 20 of 20 tries, each time with a birth time of
 * its own; on macOS (APFS), in 0 of 20. With a key of device and inode number
 * alone, the new directory met the removed one's store: `rollback` refused with
 * "recorded for a directory created at another time" where it should have said
 * "No backup found" or restored the archive inside the tree, the new
 * directory's store already held the removed directory's run before any
 * `--fix`, and `--fix` moved that store aside. Tests in seven files of this
 * suite failed that way on Linux and passed on macOS.
 *
 * The key now carries the birth time too. These cells reproduce the reuse on
 * any filesystem: the new directory reports the removed one's device and inode
 * number, with its own birth time, to the bigint `stat` the store takes of it.
 * Nothing else is simulated.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { existsSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { stat } from 'fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { describeArchiveStore, findArchiveStore } from '../../src/store/archive-store';
import { tempDir } from '../helpers/temp-dir';
import { storeDirOf, storeRuns } from '../helpers/backup-store';

/** The directory that reports a removed directory's device and inode number, while a cell runs. */
const reuse = vi.hoisted(() => ({
  current: undefined as { real: string; dev: bigint; ino: bigint } | undefined,
}));

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  const realStat = actual.stat as (p: unknown, opts?: { bigint?: boolean }) => Promise<object>;
  return {
    ...actual,
    stat: vi.fn(async (p: unknown, opts?: { bigint?: boolean }) => {
      const st = await realStat(p, opts);
      const r = reuse.current;
      if (!r || !opts?.bigint || String(p) !== r.real) return st;
      return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { dev: r.dev, ino: r.ino });
    }),
  };
});

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/** A tree `--fix` changes: the token in `config.json` is replaced by a reference. */
function fixableTree(prefix: string, port: number): string {
  const dir = tempDir(prefix);
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port }, null, 2)}\n`);
  return dir;
}

const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');

async function fix(target: string): Promise<void> {
  await new HardeningScanner().scan({ targetDir: target, autoFix: true });
  expect(liveConfig(target), 'the fix did not redact the credential; this cell measures nothing').toContain('${GITHUB_TOKEN}');
}

/** Every file under `dir` with its bytes, so a later read proves nothing in it was moved, removed or rewritten. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (rel: string): void => {
    for (const e of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = path.join(rel, e.name);
      if (e.isDirectory()) walk(r);
      else out[r] = readFileSync(path.join(dir, r), 'utf-8');
    }
  };
  walk('');
  return out;
}

/**
 * Fix a directory, remove it, and create the next one, which reports the
 * removed directory's device and inode number as a Linux filesystem would.
 */
async function removedThenReused(): Promise<{ next: string; removedStore: string }> {
  const removed = fixableTree('hma-376-removed-', 1111);
  await fix(removed);
  const removedStore = await storeDirOf(removed);
  expect(await storeRuns(removed), 'the removed directory left no run in the store').toHaveLength(1);
  const removedId = statSync(removed, { bigint: true });
  rmSync(removed, { recursive: true, force: true });

  const next = fixableTree('hma-376-next-', 2222);
  reuse.current = { real: realpathSync.native(next), dev: removedId.dev, ino: removedId.ino };
  const seen = (await stat(realpathSync.native(next), { bigint: true })) as import('node:fs').BigIntStats;
  expect([seen.dev, seen.ino], 'the new directory does not report the removed one\'s identity; this cell measures nothing')
    .toEqual([removedId.dev, removedId.ino]);
  expect(seen.birthtimeNs, 'the two directories report one birth time, so a reused identity cannot be told apart')
    .not.toBe(removedId.birthtimeNs);
  return { next, removedStore };
}

describe('#376 a directory that takes a removed directory\'s inode number gets a store of its own', () => {
  afterEach(() => {
    reuse.current = undefined;
  });

  it('finds no backup for the new directory, and leaves the removed directory\'s store as it was', async () => {
    const { next, removedStore } = await removedThenReused();
    const before = snapshot(removedStore);

    expect(await storeDirOf(next), 'the new directory was given the removed directory\'s store').not.toBe(removedStore);
    expect((await findArchiveStore(next)).kind).toBe('none');
    expect(await storeRuns(next), 'the removed directory\'s run was counted as the new one\'s').toEqual([]);
    expect(await describeArchiveStore(next)).toBeUndefined();
    await expect(
      new HardeningScanner().rollback(next),
      'rollback of a directory with no backup did not say so',
    ).rejects.toThrow(/No backup found/);

    expect(snapshot(removedStore), 'the removed directory\'s store changed').toEqual(before);
  }, 120_000);

  it('--fix takes a store of its own, which rollback restores from, and moves nothing aside', async () => {
    const { next, removedStore } = await removedThenReused();
    const before = snapshot(removedStore);
    const original = liveConfig(next);

    await fix(next);

    const store = await storeDirOf(next);
    expect(store, 'the new directory was given the removed directory\'s store').not.toBe(removedStore);
    expect((await findArchiveStore(next)).kind).toBe('store');
    expect(await storeRuns(next)).toHaveLength(1);
    expect(existsSync(removedStore), 'the removed directory\'s store is gone').toBe(true);
    expect(snapshot(removedStore), 'the removed directory\'s store changed').toEqual(before);
    expect(
      readdirSync(path.dirname(store)).filter((n) => n.includes('.replaced-')),
      'a store was moved aside',
    ).toEqual([]);

    const report = await new HardeningScanner().rollback(next);
    expect(report.backupSource).toBe('store');
    expect(liveConfig(next), 'rollback did not restore the new directory\'s own pre-fix file').toBe(original);
  }, 120_000);
});
