/**
 * #1050 — the release notes say a re-created directory never gets a deleted
 * directory's backups, which holds only where the filesystem records when a
 * directory was created.
 *
 * The store key is `<dev>-<ino>-<birth>` (#376). A filesystem that reports no
 * birth time gives 0, the key is then `<dev>-<ino>-0` for every directory with
 * that device and inode number, and a record with a zero birth time is accepted
 * for any of them. The module docblock of `src/store/archive-store.ts` says so.
 * The pending #376 entry said the opposite without a condition: "A directory
 * created after another one was deleted does not get the deleted directory's
 * backups, even when the filesystem gives it the same inode number."
 *
 * The first cell measures what the store does there: every bigint `stat` the
 * store takes reports a birth time of 0, and the new directory reports the
 * removed one's device and inode number. Nothing else is simulated. The second
 * cell holds the release notes to that measurement.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { stat } from 'fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { findArchiveStore } from '../../src/store/archive-store';
import { sectionRecording, virtualChangelog } from '../helpers/changelog-record';
import { tempDir } from '../helpers/temp-dir';
import { storeDirOf, storeRuns } from '../helpers/backup-store';

/** What the filesystem reports to a bigint `stat` while a cell runs. */
const filesystem = vi.hoisted(() => ({
  /** True on a filesystem that reports no birth time: every bigint `stat` gives 0. */
  noBirthTime: false,
  /** The directory that reports a removed directory's device and inode number. */
  reuse: undefined as { real: string; dev: bigint; ino: bigint } | undefined,
}));

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  const realStat = actual.stat as (p: unknown, opts?: { bigint?: boolean }) => Promise<object>;
  return {
    ...actual,
    stat: vi.fn(async (p: unknown, opts?: { bigint?: boolean }) => {
      const st = await realStat(p, opts);
      if (!filesystem.noBirthTime || !opts?.bigint) return st;
      const r = filesystem.reuse;
      const identity = r && String(p) === r.real ? { dev: r.dev, ino: r.ino } : {};
      return Object.assign(Object.create(Object.getPrototypeOf(st)), st, identity, { birthtimeNs: BigInt(0) });
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

/** The bullet of the release notes that makes the claim, on one line. */
function backupStoreEntry(): string {
  const claim = /does\s+not\s+get\s+the\s+deleted\s+directory's\s+backups/;
  const bullet = sectionRecording(virtualChangelog(), claim)
    .split(/^- /m)
    .find((b) => claim.test(b));
  expect(bullet, 'the claim is not in a bullet of the section that records it').toBeDefined();
  return bullet!.replace(/\s+/g, ' ');
}

/** The sentences of `text` that match `needle`. */
function sentencesMatching(text: string, needle: RegExp): string[] {
  return text.split(/(?<=\.)\s+(?=[A-Z])/).filter((s) => needle.test(s));
}

describe('#1050 a filesystem that reports no birth time tells a re-created directory from a removed one by nothing', () => {
  afterEach(() => {
    filesystem.noBirthTime = false;
    filesystem.reuse = undefined;
  });

  it('gives the new directory the removed directory\'s store, and rollback restores the removed directory\'s file', async () => {
    filesystem.noBirthTime = true;

    const removed = fixableTree('hma-1050-removed-', 1111);
    const removedOriginal = liveConfig(removed);
    await fix(removed);
    const removedStore = await storeDirOf(removed);
    expect(path.basename(removedStore), 'the store key carries a birth time; this cell measures nothing').toMatch(/-0$/);
    expect(await storeRuns(removed), 'the removed directory left no run in the store').toHaveLength(1);
    const removedId = statSync(removed, { bigint: true });
    rmSync(removed, { recursive: true, force: true });

    const next = fixableTree('hma-1050-next-', 2222);
    filesystem.reuse = { real: realpathSync.native(next), dev: removedId.dev, ino: removedId.ino };
    const seen = (await stat(realpathSync.native(next), { bigint: true })) as import('node:fs').BigIntStats;
    expect(
      [seen.dev, seen.ino, seen.birthtimeNs],
      'the new directory does not report the removed one\'s identity with no birth time; this cell measures nothing',
    ).toEqual([removedId.dev, removedId.ino, BigInt(0)]);

    // If any of these stops holding, such a filesystem tells the two
    // directories apart: drop the condition from the release notes and from
    // the cell below in the same change.
    expect(await storeDirOf(next), 'the new directory has a store of its own').toBe(removedStore);
    expect((await findArchiveStore(next)).kind).toBe('store');
    expect(await storeRuns(next), 'the removed directory\'s run is not counted as the new one\'s').toHaveLength(1);

    const report = await new HardeningScanner().rollback(next);
    expect(report.backupSource).toBe('store');
    expect(liveConfig(next), 'rollback did not restore the removed directory\'s file here').toBe(removedOriginal);
  }, 120_000);
});

describe('#1050 the release notes limit the claim to a filesystem that records when a directory was created', () => {
  it('states the condition in the sentence that makes the claim', () => {
    const claims = sentencesMatching(backupStoreEntry(), /does not get the deleted directory's backups/);
    expect(claims, 'the claim is made in no sentence, or in more than one').toHaveLength(1);
    expect(
      claims[0],
      'the sentence promises a re-created directory never gets a deleted directory\'s backups, on every filesystem',
    ).toMatch(/filesystem that records when a directory was created/);
  });

  it('says what happens on a filesystem that reports no creation time', () => {
    const other = sentencesMatching(backupStoreEntry(), /filesystem that reports no creation time/);
    expect(other, 'the entry does not name the filesystem the claim leaves out').toHaveLength(1);
    expect(other[0], 'the entry does not say whose backups the new directory uses there')
      .toMatch(/given a deleted directory's inode number uses that directory's backups/);
  });
});
