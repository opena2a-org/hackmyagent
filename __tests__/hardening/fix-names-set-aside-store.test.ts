/**
 * #1035 — `--fix` says when it sets a backup store aside, and `rollback` names
 * `hackmyagent backups`.
 *
 * Measured before this change: a store under the target's key whose
 * `target.json` HackMyAgent did not write was renamed to
 * `<key>.replaced-<time>-<random>` by the next `secure --fix`, and the run
 * printed nothing about it. The renamed store can hold another directory's
 * pre-fix copies, credentials among them.
 *
 * Now `prepareArchiveStore` returns the path it moved the store to, the text
 * report prints one line naming it and the command that lists it, and the
 * `--json` output and the `Backups:` line are what they were.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { prepareArchiveStore } from '../../src/store/archive-store';
import { assertDistFresh } from '../helpers/dist-freshness';
import { storeDirOf } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

/** Synthesised at runtime, never a literal in the source tree. */
const FAKE_GH_TOKEN = `${['gh', 'p_'].join('')}${'a'.repeat(36)}`;

function fixableTree(): string {
  const dir = tempDir('hma-1035-proj-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`);
  return dir;
}

interface Spawned { stdout: string; stderr: string; status: number | null }

/** The built CLI with the suite's own backup store (vitest.setup.ts sets HMA_BACKUP_HOME). */
function hma(args: string[], cwd: string): Spawned {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' };
  delete env.HMA_CLI_PREFIX;
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120_000, cwd, env });
  // eslint-disable-next-line no-control-regex
  const strip = (s: string | null): string => (s ?? '').replace(/\x1b\[[0-9;]*m/g, '');
  return { stdout: strip(res.stdout), stderr: strip(res.stderr), status: res.status };
}

/** A `target.json` HackMyAgent did not write: the next `--fix` sets the store aside. */
function spoilRecord(store: string): void {
  writeFileSync(path.join(store, 'target.json'), 'not a record HackMyAgent wrote\n');
}

/** The stores set aside from `store`, as absolute paths. */
function setAsideFrom(store: string): string[] {
  return readdirSync(path.dirname(store))
    .filter((n) => n.startsWith(`${path.basename(store)}.replaced-`))
    .map((n) => path.join(path.dirname(store), n))
    .sort();
}

const FIX_ARGS = ['--fix', '--static-only', '--no-machine-posture'];
const setAsideLines = (out: string): string[] => out.split('\n').filter((l) => l.startsWith('Backup store set aside:'));

describe('#1035 prepareArchiveStore returns the path it set a store aside to', () => {
  it('returns no setAside for a new or a recorded store, and the moved path for a store it moved', async () => {
    const target = fixableTree();

    const first = await prepareArchiveStore(target);
    expect(first.setAside, 'a new store was reported as set aside').toBeUndefined();
    expect(first.dir).toBe(realpathSync.native(await storeDirOf(target)));

    const again = await prepareArchiveStore(target);
    expect(again).toEqual({ dir: first.dir });

    spoilRecord(first.dir);
    const moved = await prepareArchiveStore(target);
    expect(moved.dir, 'the target\'s store moved to another path').toBe(first.dir);
    expect(moved.setAside, 'a store that was moved aside was not reported').toBeDefined();
    expect(setAsideFrom(first.dir)).toEqual([moved.setAside]);
    expect(readFileSync(path.join(moved.setAside!, 'target.json'), 'utf-8'), 'the store set aside is not the one that was there')
      .toBe('not a record HackMyAgent wrote\n');

    const after = await prepareArchiveStore(target);
    expect(after.setAside, 'a store recorded by the last call was reported as set aside again').toBeUndefined();
  });
});

describe('#1035 --fix prints one line when it sets a store aside', () => {
  beforeAll(assertDistFresh);

  it('names the moved store and hackmyagent backups, and leaves the Backups line as it was', async () => {
    const target = fixableTree();
    const cwd = tempDir('hma-1035-cwd-');

    const first = hma(['secure', target, ...FIX_ARGS], cwd);
    expect(first.stdout, 'the run took no backup; this cell measures nothing').toContain('Backup created:');
    expect(setAsideLines(first.stdout), 'a run that moved nothing said it did').toEqual([]);

    const store = await storeDirOf(target);
    spoilRecord(store);
    const second = hma(['secure', target, ...FIX_ARGS], cwd);
    const aside = setAsideFrom(store);
    expect(aside, 'the run did not set the store aside; this cell measures nothing').toHaveLength(1);

    expect(setAsideLines(second.stdout)).toEqual([
      `Backup store set aside: ${aside[0]} — the store under this directory's key was not recorded for this directory, `
      + 'so --fix moved it there, deleted nothing in it, and started a new one. `hackmyagent backups` lists it.',
    ]);
    expect(second.stdout).toContain('Backup created:');
    // The store set aside held this directory's first run; the new store holds the second.
    expect(second.stdout.split('\n').filter((l) => l.startsWith('Backups: '))).toEqual([
      expect.stringMatching(/^Backups: 1 --fix backup of this directory is kept outside it at /),
    ]);
  }, 300_000);

  it('adds nothing to the --json output', async () => {
    const target = fixableTree();
    const cwd = tempDir('hma-1035-cwd-');

    hma(['secure', target, ...FIX_ARGS, '--json'], cwd);
    const store = await storeDirOf(target);
    spoilRecord(store);
    const run = hma(['secure', target, ...FIX_ARGS, '--json'], cwd);

    expect(setAsideFrom(store), 'the run did not set the store aside; this cell measures nothing').toHaveLength(1);
    const parsed = JSON.parse(run.stdout) as Record<string, unknown>;
    expect(Object.keys(parsed).filter((k) => /aside|replaced/i.test(k))).toEqual([]);
    expect(run.stdout).not.toContain('.replaced-');
    expect(run.stdout + run.stderr).not.toContain('set aside');
  }, 300_000);
});

describe('#1035 rollback names hackmyagent backups', () => {
  beforeAll(assertDistFresh);

  it('in --help', () => {
    const help = hma(['rollback', '--help'], tempDir('hma-1035-cwd-'));
    expect(help.status).toBe(0);
    expect(help.stdout.replace(/\s+/g, ' ')).toContain(
      'hackmyagent backups lists every backup store, the directory each was last used for, and whether rollback '
      + 'restores from it.',
    );
  }, 120_000);

  it('in the error for a directory with no backup', () => {
    const target = tempDir('hma-1035-nobackup-');
    const run = hma(['rollback', target], tempDir('hma-1035-cwd-'));
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(
      '  To list every backup store in that root and the directory each was last used for, run: hackmyagent backups',
    );
  }, 120_000);
});
