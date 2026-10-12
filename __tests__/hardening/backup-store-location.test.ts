/**
 * #376 — where the backup store is, and what `--fix` and `rollback` do when it
 * cannot be there.
 *
 * `--fix` keeps its pre-fix copies in a per-user store outside the scanned
 * tree: `$HMA_BACKUP_HOME`, else `$OPENA2A_HOME/backups`, else
 * `~/.opena2a/backups`, one directory per target keyed by the target's
 * filesystem identity. These cells pin the location contract itself.
 *
 * A relative store root. Measured before this was refused: with
 * `HMA_BACKUP_HOME=relstore`, `--fix` run from directory A put the store at
 * `A/relstore/...`, and `rollback` in the same environment from directory B
 * exited 1 with "No backup found", while from A it restored 3 files. The
 * backups existed and the command that restores them said they did not.
 *
 * The mode of a directory the user named. Measured before this was fixed: an
 * existing `HMA_BACKUP_HOME` directory was `drwxr-xr-x` before `--fix` and
 * `drwx------` after it. What HackMyAgent creates inside is private; a
 * directory the user created keeps the mode they gave it.
 *
 * And what `rollback` does with the store: it follows a target that was moved
 * and renamed, keeps two trees of one name apart, reports failure for a store
 * that was deleted or that belongs to another directory, and a home directory
 * that cannot hold a store makes `--fix` detect only.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { describeArchiveStore, findArchiveStore, prepareArchiveStore } from '../../src/store/archive-store';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun, storeDirOf } from '../helpers/backup-store';

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/** A tree `--fix` changes: the token in `config.json` is replaced by a reference. */
function fixableTree(prefix = 'hma-376-loc-'): string {
  const dir = tempDir(prefix);
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`);
  return dir;
}

const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');
/** The directory as the store spells it: its real path (macOS's `/var` is a link). */
const realDir = (dir: string): string => realpathSync.native(dir);
const mode = (p: string): number => statSync(p).mode & 0o777;

interface Spawned { stdout: string; stderr: string; status: number | null }

/**
 * The built CLI, in `cwd`, with exactly the store variables the cell names.
 * `HMA_BACKUP_HOME` from vitest.setup.ts is dropped first, so a cell that sets
 * only `OPENA2A_HOME` measures that variable and not the suite's own store.
 */
function hma(args: string[], cwd: string, storeEnv: Record<string, string>): Spawned {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' };
  delete env.HMA_BACKUP_HOME;
  delete env.OPENA2A_HOME;
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    cwd,
    env: { ...env, ...storeEnv },
  });
  // eslint-disable-next-line no-control-regex
  const strip = (s: string | null): string => (s ?? '').replace(/\x1b\[[0-9;]*m/g, '');
  return { stdout: strip(res.stdout), stderr: strip(res.stderr), status: res.status };
}

interface FixJson { backupPath?: string; findings: Array<{ checkId: string; passed: boolean; message?: string; fix?: string }> }

describe('#376 a backup store root that is not absolute is refused', () => {
  beforeAll(assertDistFresh);

  // Each row sets ONE variable to a relative path. `created` is the directory
  // a run that resolved it against the working directory would have made.
  it.each([
    {
      variable: 'HMA_BACKUP_HOME',
      storeEnv: (home: string): Record<string, string> => ({ HOME: home, OPENA2A_HOME: home, HMA_BACKUP_HOME: 'relstore' }),
      created: 'relstore',
    },
    {
      variable: 'OPENA2A_HOME',
      storeEnv: (home: string): Record<string, string> => ({ HOME: home, OPENA2A_HOME: 'rel' }),
      created: path.join('rel', 'backups'),
    },
  ])('--fix detects only and rollback names $variable', ({ variable, storeEnv, created }) => {
    const target = fixableTree();
    const home = tempDir('hma-376-home-');
    const cwdA = tempDir('hma-376-cwd-a-');
    const cwdB = tempDir('hma-376-cwd-b-');
    const before = liveConfig(target);

    const fix = hma(['secure', target, '--fix', '--json', '--static-only', '--no-machine-posture'], cwdA, storeEnv(home));
    const result = JSON.parse(fix.stdout) as FixJson;
    const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');

    expect(refused, 'the run fixed with a store resolved against the working directory').toHaveLength(1);
    expect(refused[0].passed).toBe(false);
    expect(refused[0].message, 'the refusal does not name the variable that is relative').toContain(variable);
    expect(refused[0].fix, 'the remedy does not name the variable to set').toContain(variable);
    expect(result.backupPath, 'a run that took no backup reported one').toBeUndefined();
    expect(liveConfig(target), 'a detect-only run changed the live file').toBe(before);
    expect(existsSync(path.join(cwdA, created)), `a store was created under the working directory at ${created}`).toBe(false);

    // The same environment from another directory: the store cannot be located,
    // and the report says which variable to correct. "No backup found" would
    // tell the user to run --fix again, which is not the remedy.
    const rollback = hma(['rollback', target], cwdB, storeEnv(home));
    const said = rollback.stdout + rollback.stderr;
    expect(rollback.status, 'rollback claimed success with a store it could not locate').not.toBe(0);
    expect(said).toContain(variable);
    expect(said).not.toContain('No backup found');
    expect(existsSync(path.join(cwdB, created))).toBe(false);
    expect(liveConfig(target)).toBe(before);
  }, 180_000);

  it('creates nothing at all under the working directory for a relative HMA_BACKUP_HOME', () => {
    const target = fixableTree();
    const home = tempDir('hma-376-home-');
    const cwd = tempDir('hma-376-cwd-');

    hma(['secure', target, '--fix', '--json', '--static-only', '--no-machine-posture'], cwd,
      { HOME: home, OPENA2A_HOME: home, HMA_BACKUP_HOME: 'relstore' });

    expect(readdirSync(cwd)).toEqual([]);
  }, 180_000);
});

describe('#376 the store lookup and the store setup refuse a relative root', () => {
  let saved: { backup?: string; opena2a?: string };

  beforeEach(() => {
    saved = { backup: process.env.HMA_BACKUP_HOME, opena2a: process.env.OPENA2A_HOME };
  });

  afterEach(() => {
    if (saved.backup === undefined) delete process.env.HMA_BACKUP_HOME; else process.env.HMA_BACKUP_HOME = saved.backup;
    if (saved.opena2a === undefined) delete process.env.OPENA2A_HOME; else process.env.OPENA2A_HOME = saved.opena2a;
  });

  it.each([
    { variable: 'HMA_BACKUP_HOME', set: (): void => { process.env.HMA_BACKUP_HOME = 'relstore'; } },
    { variable: 'OPENA2A_HOME', set: (): void => { delete process.env.HMA_BACKUP_HOME; process.env.OPENA2A_HOME = 'rel'; } },
  ])('for $variable', async ({ variable, set }) => {
    const target = fixableTree();
    set();

    const found = await findArchiveStore(target);
    expect(found.kind, 'a relative root was resolved against the working directory').toBe('unknown');
    expect(found.kind === 'unknown' ? found.reason : '').toContain(variable);

    await expect(prepareArchiveStore(target)).rejects.toMatchObject({
      code: 'HMA-BACKUP-RELATIVE-ROOT',
      message: expect.stringContaining(variable),
    });

    // The scanner turns that into the unknown-store refusal, never into the
    // "no run in the store" branch that falls back to an archive in the tree.
    await expect(new HardeningScanner().rollback(target)).rejects.toThrow(variable);
  }, 60_000);

  it('still treats an empty HMA_BACKUP_HOME as unset', async () => {
    const target = fixableTree();
    const home = tempDir('hma-376-home-');
    process.env.HMA_BACKUP_HOME = '';
    process.env.OPENA2A_HOME = home;

    expect(path.dirname(await storeDirOf(target))).toBe(path.join(realDir(home), 'backups'));
  });
});

describe.skipIf(process.platform === 'win32')('#376 the mode of the store and of a directory the user named', () => {
  let saved: { backup?: string; opena2a?: string };

  beforeEach(() => {
    saved = { backup: process.env.HMA_BACKUP_HOME, opena2a: process.env.OPENA2A_HOME };
  });

  afterEach(() => {
    if (saved.backup === undefined) delete process.env.HMA_BACKUP_HOME; else process.env.HMA_BACKUP_HOME = saved.backup;
    if (saved.opena2a === undefined) delete process.env.OPENA2A_HOME; else process.env.OPENA2A_HOME = saved.opena2a;
  });

  const fix = async (target: string): Promise<void> => {
    await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    expect(liveConfig(target), 'the fix did not redact the credential; this cell measures nothing').toContain('${GITHUB_TOKEN}');
  };

  it('leaves an existing HMA_BACKUP_HOME directory with the mode the user gave it', async () => {
    const target = fixableTree();
    const named = path.join(tempDir('hma-376-named-'), 'X');
    mkdirSync(named);
    chmodSync(named, 0o755);
    process.env.HMA_BACKUP_HOME = named;

    await fix(target);

    expect(mode(named).toString(8), 'the run changed the mode of a directory the user created').toBe('755');
    const store = await storeDirOf(target);
    expect(path.dirname(store)).toBe(realDir(named));
    expect(mode(store).toString(8)).toBe('700');
    const run = await latestStoreRun(target);
    expect(mode(run).toString(8)).toBe('700');
    expect(mode(path.join(store, 'target.json')).toString(8)).toBe('600');
    expect(mode(path.join(run, 'config.json')).toString(8)).toBe('600');
    expect(mode(path.join(run, '.manifest.json')).toString(8)).toBe('600');
  }, 120_000);

  it('creates an absent HMA_BACKUP_HOME 0700 and leaves the parent it had to create at the default', async () => {
    const target = fixableTree();
    const parent = path.join(tempDir('hma-376-named-'), 'Y');
    const named = path.join(parent, 'Z');
    process.env.HMA_BACKUP_HOME = named;

    await fix(target);

    expect(mode(named).toString(8)).toBe('700');
    expect(mode(parent) & 0o700, 'the parent is not usable by its owner').toBe(0o700);
    expect(mode(await storeDirOf(target)).toString(8)).toBe('700');
  }, 120_000);

  it('keeps backups/ under the user store 0700 even when it was left open', async () => {
    const target = fixableTree();
    const home = tempDir('hma-376-home-');
    const backups = path.join(home, 'backups');
    mkdirSync(backups);
    chmodSync(backups, 0o755);
    delete process.env.HMA_BACKUP_HOME;
    process.env.OPENA2A_HOME = home;

    await fix(target);

    expect(mode(backups).toString(8), 'backups/ is HackMyAgent\'s own directory and holds plaintext copies').toBe('700');
    expect(mode(await storeDirOf(target)).toString(8)).toBe('700');
  }, 120_000);
});

/**
 * RULE 6 of the #376 ruling: what `rollback` does with the store for a target
 * that moved, shares its name with another, cannot have a store, lost its
 * store, or has the filesystem identity another directory used to have. Each
 * cell fixes a real tree first, so the backup under test is one `--fix` made.
 */
describe('#376 rollback finds a target\'s backups by the directory, not by its path', () => {
  const fix = async (target: string): Promise<string> => {
    const before = liveConfig(target);
    await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    expect(liveConfig(target), 'the fix did not redact the credential; this cell measures nothing').toContain('${GITHUB_TOKEN}');
    return before;
  };

  it('restores a target that was moved to another parent and renamed', async () => {
    const target = fixableTree();
    const original = await fix(target);
    const storeBefore = await storeDirOf(target);

    const moved = path.join(tempDir('hma-376-elsewhere-'), 'renamed-project');
    renameSync(target, moved);

    // A store keyed by the path would be looked for under the new path's key,
    // and the backups would be reported missing.
    expect(await storeDirOf(moved), 'the store is keyed by something the move changed').toBe(storeBefore);
    const report = await new HardeningScanner().rollback(moved);

    expect(report.backupSource).toBe('store');
    expect(report.restored).toContain('config.json');
    expect(liveConfig(moved), 'the moved directory did not get its pre-fix file back').toBe(original);
  }, 120_000);

  it('restores through a symbolic link to the target', async () => {
    const target = fixableTree();
    const original = await fix(target);
    const link = path.join(tempDir('hma-376-link-'), 'link-to-project');
    symlinkSync(target, link);

    expect(await storeDirOf(link), 'the link has a store of its own').toBe(await storeDirOf(target));
    const report = await new HardeningScanner().rollback(link);

    expect(report.backupSource).toBe('store');
    expect(liveConfig(target), 'rollback through the link did not restore the target').toBe(original);
  }, 120_000);

  it('keeps two trees with the same name apart', async () => {
    const a = path.join(tempDir('hma-376-parent-a-'), 'proj');
    const b = path.join(tempDir('hma-376-parent-b-'), 'proj');
    for (const [dir, port] of [[a, 1111], [b, 2222]] as const) {
      mkdirSync(dir);
      writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
      writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port }, null, 2)}\n`);
    }
    const originalA = await fix(a);
    const originalB = await fix(b);
    expect(originalA).not.toBe(originalB);
    expect(await storeDirOf(a), 'two directories named proj share one store').not.toBe(await storeDirOf(b));

    // A's rollback restores A's bytes, not the newer run that B made, and
    // leaves B fixed with its backup intact.
    await new HardeningScanner().rollback(a);
    expect(liveConfig(a)).toBe(originalA);
    expect(liveConfig(b), 'rolling back one tree changed the other').toContain('${GITHUB_TOKEN}');

    await new HardeningScanner().rollback(b);
    expect(liveConfig(b)).toBe(originalB);
  }, 180_000);

  it('reports failure, and restores nothing, once the store has been deleted', async () => {
    const target = fixableTree();
    await fix(target);
    const fixed = liveConfig(target);
    rmSync(await storeDirOf(target), { recursive: true, force: true });

    await expect(
      new HardeningScanner().rollback(target),
      'rollback claimed success with no backup to restore from',
    ).rejects.toThrow(/No backup found/);
    expect(liveConfig(target), 'a failed rollback changed the live file').toBe(fixed);
    expect(existsSync(await storeDirOf(target)), 'a failed rollback re-created the store').toBe(false);
  }, 120_000);

  it('refuses a store recorded for another directory, and --fix moves it aside without deleting it', async () => {
    const target = fixableTree();
    const original = await fix(target);
    const fixed = liveConfig(target);
    const store = await storeDirOf(target);
    const firstRun = path.basename(await latestStoreRun(target));

    // The state a reused inode leaves: the store under this identity names a
    // directory that was created at another time.
    const recordFile = path.join(store, 'target.json');
    const record = JSON.parse(readFileSync(recordFile, 'utf-8')) as { birthtimeNs: string; lastKnownPath: string };
    expect(record.birthtimeNs, 'this filesystem reports no birth time, so a reused identity cannot be told apart').not.toBe('0');
    writeFileSync(recordFile, JSON.stringify({ ...record, birthtimeNs: '1', lastKnownPath: '/somewhere/else' }));

    expect((await findArchiveStore(target)).kind).toBe('other-directory');
    expect(await describeArchiveStore(target), 'another directory\'s backups were counted as this one\'s').toBeUndefined();
    await expect(
      new HardeningScanner().rollback(target),
      'rollback restored another directory\'s files here',
    ).rejects.toThrow(/created at another time.*\/somewhere\/else/s);
    expect(liveConfig(target)).toBe(fixed);

    // The next --fix needs a store of its own. The other directory's is kept,
    // whole, under a name that says what happened to it.
    writeFileSync(path.join(target, 'config.json'), original);
    await fix(target);

    const aside = readdirSync(path.dirname(store)).filter((n) => n.startsWith(`${path.basename(store)}.replaced-`));
    expect(aside, 'the other directory\'s store was adopted or deleted').toHaveLength(1);
    expect(
      readFileSync(path.join(path.dirname(store), aside[0], firstRun, 'config.json'), 'utf-8'),
      'the copies in the store that was moved aside are gone',
    ).toBe(original);
    expect((await findArchiveStore(target)).kind).toBe('store');
    expect(path.basename(await latestStoreRun(target)), 'the new store adopted the other directory\'s run').not.toBe(firstRun);
    await new HardeningScanner().rollback(target);
    expect(liveConfig(target)).toBe(original);
  }, 180_000);
});

describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
  '#376 a home directory that cannot hold a store',
  () => {
    beforeAll(assertDistFresh);

    it('--fix detects only and does not crash when HOME is read-only', () => {
      const target = fixableTree();
      const before = liveConfig(target);
      const home = tempDir('hma-376-rohome-');
      chmodSync(home, 0o555);
      try {
        // No override: the store would be `$HOME/.opena2a/backups`.
        const fix = hma(['secure', target, '--fix', '--json', '--static-only', '--no-machine-posture'], home, { HOME: home });

        expect(fix.stdout + fix.stderr, 'the run crashed').not.toMatch(/\n\s+at .*:\d+:\d+/);
        const result = JSON.parse(fix.stdout) as FixJson;
        const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');
        expect(refused, 'the run did not say that it skipped the fixes').toHaveLength(1);
        expect(refused[0].passed).toBe(false);
        expect(refused[0].fix, 'the remedy does not name the override').toContain('HMA_BACKUP_HOME');
        expect(result.findings.some((f) => f.checkId === 'CRED-001' && !f.passed), 'detection was lost with the backup').toBe(true);
        expect(result.backupPath).toBeUndefined();
        expect(liveConfig(target), 'a fix landed with no backup to roll back to').toBe(before);
        expect(existsSync(path.join(target, '.hackmyagent-backup')), 'the run fell back to a backup inside the tree').toBe(false);
        expect(readdirSync(home), 'something was written into the read-only home').toEqual([]);

        const rollback = hma(['rollback', target], home, { HOME: home });
        expect(rollback.status, 'rollback claimed success with no store').not.toBe(0);
        expect(rollback.stdout + rollback.stderr).toContain('No backup found');
      } finally {
        chmodSync(home, 0o755);
      }
    }, 180_000);
  },
);

/**
 * `~/.opena2a` on a fresh home, with neither override set. Measured before the
 * store setup created it 0700: a first `secure --fix` left it `drwxr-xr-x` at
 * umask 022 and `drwxrwxrwx` at umask 000, because the store setup created it
 * before the OpenA2A user config, which creates it 0700 and leaves an existing
 * one as it is.
 */
describe.skipIf(process.platform === 'win32')('#376 the user store a first --fix creates is private', () => {
  beforeAll(assertDistFresh);

  it.each(['000', '022'])('leaves $HOME/.opena2a drwx------ at umask %s', (umask) => {
    const target = fixableTree();
    const home = tempDir('hma-376-freshhome-');
    const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', HOME: home };
    delete env.HMA_BACKUP_HOME;
    delete env.OPENA2A_HOME;
    const res = spawnSync(
      '/bin/sh',
      ['-c', `umask ${umask} && exec "$@"`, 'sh', process.execPath, CLI, 'secure', target, '--fix', '--json', '--static-only', '--no-machine-posture'],
      { encoding: 'utf8', timeout: 120_000, cwd: home, env },
    );

    const result = JSON.parse(res.stdout) as FixJson;
    expect(result.backupPath, 'the run took no backup; this cell measures nothing').toBeDefined();
    expect(realpathSync.native(result.backupPath as string).startsWith(realDir(path.join(home, '.opena2a', 'backups')) + path.sep)).toBe(true);
    expect(liveConfig(target)).toContain('${GITHUB_TOKEN}');
    expect(mode(path.join(home, '.opena2a')).toString(8), 'the run created the user store open to others').toBe('700');
  }, 180_000);
});

/**
 * RULE 4(b) of the #376 ruling: every later `secure` of a target with backups
 * in the store prints one line with their count, the path and the command that
 * deletes them. Measured before the benchmark paths printed it: 1 line on
 * `secure`, 0 on `secure -b oasb-1`. `-b` is the same scan read against a
 * control list, and the copies it does not mention are just as plaintext.
 */
describe('#376 every secure text report says what the store holds for the directory', () => {
  beforeAll(assertDistFresh);

  /** The spawned CLI reads the store this file's in-process `--fix` runs wrote to. */
  const sameStore = (home: string): Record<string, string> => ({
    HOME: home,
    OPENA2A_HOME: home,
    HMA_BACKUP_HOME: process.env.HMA_BACKUP_HOME as string,
  });
  const backupsLines = (out: string): string[] => out.split('\n').filter((l) => l.startsWith('Backups: '));

  it.each([
    { report: 'secure', args: [] as string[] },
    { report: 'secure -b oasb-1', args: ['-b', 'oasb-1'] },
    { report: 'secure -b oasb-2', args: ['-b', 'oasb-2'] },
  ])('$report prints one Backups line naming the store and the command that deletes it', async ({ args }) => {
    const target = fixableTree();
    await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const store = await storeDirOf(target);
    const home = tempDir('hma-376-home-');

    const run = hma(['secure', target, ...args, '--static-only', '--no-machine-posture'], home, sameStore(home));

    const lines = backupsLines(run.stdout);
    expect(lines, `the report does not say the store holds a backup of this directory\n${run.stdout.slice(-600)}`).toHaveLength(1);
    expect(lines[0]).toMatch(/^Backups: 1 --fix backup of this directory/);
    expect(lines[0]).toContain(store);
    expect(lines[0]).toContain(`rm -rf ${store}`);
  }, 180_000);

  /**
   * What the store holds is every backup candidate present, not only what a
   * fix changed. Measured before the words said so: a `.env` no fix touched
   * was copied into every run with its token, while the notice said the
   * backup held "the pre-fix copies of the files this run changed" and the
   * line said the copies "can include a credential a fix removed".
   */
  it('says the backups hold every file a run backed up, .env included, and that they outlive the directory', async () => {
    const target = fixableTree();
    const env = `GITHUB_TOKEN=${FAKE_GH_TOKEN}\n`;
    writeFileSync(path.join(target, '.env'), env);
    chmodSync(path.join(target, '.env'), 0o600); // already private, so no fix touches it
    const home = tempDir('hma-376-home-');
    const noFixRemoved = /credential (?:a fix|it|the run) removed/;

    const first = hma(['secure', target, '--fix', '--static-only', '--no-machine-posture'], home, sameStore(home));

    const store = await storeDirOf(target);
    const run = await latestStoreRun(target);
    expect(readFileSync(path.join(target, '.env'), 'utf-8'), 'a fix changed .env; this cell measures nothing').toBe(env);
    expect(readFileSync(path.join(run, '.env'), 'utf-8'), 'the run did not copy .env').toBe(env);
    expect(mode(path.join(run, '.env')).toString(8)).toBe('600');

    expect(first.stdout).toContain('Backup created:');
    expect(first.stdout).toContain(
      '  It holds a copy of every file this run backed up, whether or not a fix changed it, so it can hold a credential '
      + 'that is still in use, such as one in `.env`. It is outside the scanned directory, so later scans do not report it, '
      + 'and deleting the scanned directory does not delete it. It stays until you delete it or `hackmyagent rollback` '
      + 'restores from it.\n',
    );
    expect(backupsLines(first.stdout)).toEqual([
      `Backups: 1 --fix backup of this directory is kept outside it at ${store}. It holds a copy of every file that run `
      + 'backed up, including files no fix changed, such as `.env`, so it can hold a credential that is still in use, and '
      + `it stays after this directory is deleted. Delete it once you no longer need \`hackmyagent rollback\`: rm -rf ${store}`,
    ]);
    expect(first.stdout).not.toMatch(noFixRemoved);

    const second = hma(['secure', target, '--fix', '--static-only', '--no-machine-posture'], home, sameStore(home));
    expect(backupsLines(second.stdout)).toEqual([
      `Backups: 2 --fix backups of this directory are kept outside it at ${store}. Each holds a copy of every file its run `
      + 'backed up, including files no fix changed, such as `.env`, so they can hold a credential that is still in use, and '
      + `they stay after this directory is deleted. Delete them once you no longer need \`hackmyagent rollback\`: rm -rf ${store}`,
    ]);
    expect(second.stdout).not.toMatch(noFixRemoved);
  }, 240_000);

  it('prints no Backups line for a directory the store holds nothing for', () => {
    const target = fixableTree();
    const home = tempDir('hma-376-home-');

    const run = hma(['secure', target, '-b', 'oasb-1', '--static-only', '--no-machine-posture'], home, sameStore(home));

    expect(run.stdout, 'the benchmark report never rendered, so the absence below is unmeasured').toMatch(/OASB/);
    expect(backupsLines(run.stdout)).toEqual([]);
  }, 180_000);

  it('keeps the line out of a machine-readable benchmark report', async () => {
    const target = fixableTree();
    await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const home = tempDir('hma-376-home-');

    const run = hma(['secure', target, '-b', 'oasb-1', '--format', 'sarif', '--static-only', '--no-machine-posture'], home, sameStore(home));

    expect(run.stdout).not.toContain('Backups: ');
    expect(() => JSON.parse(run.stdout), 'the SARIF document is no longer parseable').not.toThrow();
  }, 180_000);
});
