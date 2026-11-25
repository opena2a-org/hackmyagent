/**
 * #1035 (part 3): `hackmyagent backups`, spawned from the built CLI with a
 * scratch HOME and nothing else telling it where the stores are.
 *
 * Every cell runs the command the way a user would: the default store root is
 * `$HOME/.opena2a/backups`, `HMA_BACKUP_HOME` and `OPENA2A_HOME` are removed
 * from the environment unless a cell sets one, and every run of `backups` is
 * bracketed by a snapshot of the whole scratch tree (HOME, the projects, the
 * store root), which must be equal before and after: the command reads and
 * never writes.
 *
 *   - one cell per state a store can be in, the moved project among them: a
 *     project `--fix` wrote a store for is moved with `mv`, `backups` reports
 *     its store as not in use, and `rollback` run in the moved project still
 *     restores from it and exits 0;
 *   - render safety: a store root whose name a shell would execute, and one
 *     carrying terminal control characters. The output holds no control
 *     character, the delete command offered runs in a shell and deletes the
 *     store and nothing else, and no PWNED file appears anywhere;
 *   - the reused-identity cell (a directory with a store's device and inode
 *     number and another creation time) is run once more against a mutant of
 *     the built CLI that ignores the creation time, and must go red there;
 *   - exit 0, 1 and 2, and `backups delete <store dir>` exits 2 with the store
 *     directory intact.
 *
 * Not covered here: `not-owned`, which needs a directory another account owns,
 * so a second user account and root; the in-process cells of
 * backups-command.test.ts cover its rendering.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync,
  statSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const isRoot = process.getuid?.() === 0;
const onWindows = process.platform === 'win32';

/** Assembled at runtime, so the source tree holds no token-shaped literal. */
const FAKE_GH_TOKEN = `${['gh', 'p_'].join('')}${'a'.repeat(36)}`;
const FIX_ARGS = ['--fix', '--static-only', '--no-machine-posture'];

/** Matches a character a terminal acts on or breaks a line at, other than the newline that ends a line. */
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;

interface Spawned { status: number | null; stdout: string; stderr: string }

/** A scratch world: a HOME, a working directory and room for projects, all under one directory. */
interface World { base: string; home: string; cwd: string; root: string }

/**
 * The telemetry state a HOME holds once any command has run in it. The
 * telemetry library writes its install ID under `~/.config/opena2a` on the
 * first run of any command in a HOME that has none, whatever the command; a
 * later run leaves it as it is. Each world starts with it, so the snapshot
 * around `backups` stays strict over the whole tree, that directory included.
 */
let primedConfig: string;

function primeTelemetry(): void {
  primedConfig = path.join(realpathSync.native(tempDir('hma-1035-primed-')), '.config');
  const r = spawnSync(process.execPath, [BUILT_CLI, '--version'], {
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, NO_COLOR: '1', HOME: path.dirname(primedConfig) },
  });
  expect(r.status, r.stderr).toBe(0);
}

function world(): World {
  const base = realpathSync.native(tempDir('hma-1035-spawn-'));
  const home = path.join(base, 'home');
  const cwd = path.join(base, 'cwd');
  mkdirSync(home);
  mkdirSync(cwd);
  if (existsSync(primedConfig)) cpSync(primedConfig, path.join(home, '.config'), { recursive: true, preserveTimestamps: true });
  return { base, home, cwd, root: path.join(home, '.opena2a', 'backups') };
}

/**
 * The built CLI in `w.cwd`, with `w.home` as HOME and only the store variables
 * `extraEnv` names. `nodeArgs` go before the CLI path.
 */
function hma(w: World, args: string[], extraEnv: Record<string, string> = {}, nodeArgs: string[] = []): Spawned {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', HOME: w.home };
  delete env.HMA_BACKUP_HOME;
  delete env.OPENA2A_HOME;
  delete env.HMA_CLI_PREFIX;
  const r = spawnSync(process.execPath, [...nodeArgs, BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    cwd: w.cwd,
    env: { ...env, ...extraEnv },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/**
 * Every entry under `dir`, not following links, with its mode, size, mtime,
 * inode number and bytes: what a write, chmod, rename or delete would change.
 * A directory that cannot be listed is recorded as such.
 */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    let names: string[];
    try {
      names = readdirSync(d).sort();
    } catch (err) {
      out.push(`${path.relative(dir, d)} unlistable ${(err as NodeJS.ErrnoException).code}`);
      return;
    }
    for (const name of names) {
      const p = path.join(d, name);
      const st = lstatSync(p);
      let body = '';
      if (st.isSymbolicLink()) body = ` -> ${readlinkSync(p)}`;
      else if (st.isFile()) body = ` ${readFileSync(p, 'base64')}`;
      out.push(`${JSON.stringify(path.relative(dir, p))} ${st.mode} ${st.size} ${st.mtimeMs} ${st.ino}${body}`);
      if (st.isDirectory()) walk(p);
    }
  };
  walk(dir);
  return out;
}

/** `backups` with `args`, asserting that nothing under the scratch tree changed. */
function backups(w: World, args: string[] = [], extraEnv: Record<string, string> = {}, nodeArgs: string[] = []): Spawned {
  const before = snapshot(w.base);
  const r = hma(w, ['backups', ...args], extraEnv, nodeArgs);
  expect(snapshot(w.base), `backups ${args.join(' ')} changed the scratch tree`).toEqual(before);
  return r;
}

/** A project `--fix` changes: the token in `config.json` is replaced by a reference. */
function fixableProject(w: World, name = 'proj'): string {
  const dir = path.join(w.base, name);
  mkdirSync(dir);
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`);
  return dir;
}

const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');

/** `secure --fix` on `dir`, which must change it, leaving one store with one run under the root. */
function fix(w: World, dir: string, extraEnv: Record<string, string> = {}): void {
  const r = hma(w, ['secure', dir, ...FIX_ARGS], extraEnv);
  expect(liveConfig(dir), `--fix did not redact the credential; this cell measures nothing\n${r.stdout}\n${r.stderr}`)
    .toContain('${GITHUB_TOKEN}');
}

/** The store directories under `root`. */
function storesUnder(root: string): string[] {
  return readdirSync(root).sort().map((n) => path.join(root, n));
}

function identity(dir: string): { dev: string; ino: string; birthtimeNs: string } {
  const st = statSync(dir, { bigint: true });
  return { dev: st.dev.toString(), ino: st.ino.toString(), birthtimeNs: st.birthtimeNs.toString() };
}

/** A store under `key` with a record naming `lastKnownPath` (none when undefined) and one run directory. */
function handStore(root: string, key: { dev: string; ino: string; birthtimeNs: string }, lastKnownPath: string | undefined): string {
  const dir = path.join(root, `${key.dev}-${key.ino}-${key.birthtimeNs}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  if (lastKnownPath !== undefined) {
    writeFileSync(path.join(dir, 'target.json'), JSON.stringify({
      schemaVersion: 1, ...key, lastKnownPath, createdAt: '2026-11-25T00:00:00.000Z',
    }));
  }
  mkdirSync(path.join(dir, '2026-11-25-000000000-000-abcdef01'));
  return dir;
}

/** The block `backups` prints for the store at `dir`: its path line and the lines indented under it. */
function blockOf(stdout: string, dir: string): string {
  const lines = stdout.split('\n');
  const at = lines.indexOf(dir);
  expect(at, `no block for ${dir} in:\n${stdout}`).toBeGreaterThanOrEqual(0);
  const block = [lines[at]];
  for (let i = at + 1; i < lines.length && lines[i].startsWith('  '); i += 1) block.push(lines[i]);
  return block.join('\n');
}

/** Every entry under `dir` named PWNED, which `touch PWNED` run anywhere under it would create. */
function pwnedUnder(dir: string): string[] {
  const found: string[] = [];
  const walk = (d: string): void => {
    let names: string[];
    try {
      names = readdirSync(d);
    } catch {
      return;
    }
    for (const name of names) {
      const p = path.join(d, name);
      if (name === 'PWNED') found.push(p);
      if (lstatSync(p).isDirectory()) walk(p);
    }
  };
  walk(dir);
  return found;
}

const OTHER_BIRTH = /state: {4}not used: the directory at .* has this store's device and inode number and (an earlier|another) creation time/;

/**
 * The reused-identity cell: the directory at the path a store's record names
 * has the store's device and inode number and another creation time, which is
 * what a directory that took a removed directory's inode number looks like.
 * `rollback` there would not restore from the store, so `backups` must not call
 * it in use. Returns what went wrong, empty when the cell passes.
 */
function reusedIdentityCell(w: World, nodeArgs: string[] = []): string[] {
  const proj = path.join(w.base, 'reused');
  mkdirSync(proj);
  const id = identity(proj);
  const key = { ...id, birthtimeNs: (BigInt(id.birthtimeNs) + 1_000n).toString() };
  const store = handStore(w.root, key, proj);

  const r = backups(w, [], {}, nodeArgs);
  const failures: string[] = [];
  if (r.status !== 1) failures.push(`exit ${r.status}, not 1`);
  if (!r.stdout.split('\n').includes(store)) failures.push('the store is not listed');
  else {
    const block = blockOf(r.stdout, store);
    if (!OTHER_BIRTH.test(block)) failures.push(`the store is not reported as another creation time's:\n${block}`);
    if (/state: {4}in use/.test(block)) failures.push(`the store is reported in use:\n${block}`);
  }
  if (!r.stdout.includes('1 backup store: 0 in use, 1 not in use.')) failures.push('the footer does not count it as not in use');
  return failures;
}

describe.skipIf(onWindows)('#1035 hackmyagent backups, spawned with a scratch HOME', () => {
  beforeAll(() => {
    assertDistFresh();
    primeTelemetry();
  });

  describe('one cell per state', () => {
    it('no store root: exit 0, and the root is not created', () => {
      const w = world();
      const r = backups(w);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain(`No backup store root at ${w.root} (the default, under your home directory)`);
      expect(existsSync(path.join(w.home, '.opena2a'))).toBe(false);
    });

    it('in use: the store --fix wrote for a project still where it was, exit 0', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const [store] = storesUnder(w.root);
      const r = backups(w);
      expect(r.status, r.stderr).toBe(0);
      expect(blockOf(r.stdout, store)).toBe([
        store,
        `  state:    in use: rollback run in ${proj} restores from it, and has nothing to restore once it is deleted`,
        '  backups:  1 --fix run',
        `  delete:   rm -rf ${store}`,
      ].join('\n'));
      expect(r.stdout).toContain('1 backup store: 1 in use, 0 not in use.');
    });

    it('a project moved with mv: not in use where it was, and rollback in the moved project exits 0', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const [store] = storesUnder(w.root);
      const moved = path.join(w.base, 'moved-proj');
      const mv = spawnSync('mv', [proj, moved], { encoding: 'utf8' });
      expect(mv.status, mv.stderr).toBe(0);

      const r = backups(w);
      expect(r.status, r.stderr).toBe(1);
      expect(blockOf(r.stdout, store)).toContain(
        `  state:    not used: nothing is at ${proj}, where this store's directory was at its last --fix. `
        + 'If that directory was moved, rollback run in it still restores from this store',
      );
      expect(r.stdout).toContain('1 backup store: 0 in use, 1 not in use.');

      const rb = hma(w, ['rollback', moved]);
      expect(rb.status, `${rb.stdout}\n${rb.stderr}`).toBe(0);
      expect(rb.stdout).toContain('Rollback complete');
      expect(liveConfig(moved)).toContain(FAKE_GH_TOKEN);
    });

    it('another directory at the recorded path: exit 1', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const [store] = storesUnder(w.root);
      renameSync(proj, path.join(w.base, 'elsewhere'));
      mkdirSync(proj);

      const r = backups(w);
      expect(r.status, r.stderr).toBe(1);
      expect(blockOf(r.stdout, store)).toContain(`  state:    not used: another directory is at ${proj}, `);
    });

    it('reused identity: the directory there has the store\'s device and inode number and another creation time, exit 1', () => {
      expect(reusedIdentityCell(world())).toEqual([]);
    });

    it('no path, no record, a record HackMyAgent did not write, moved aside, not a directory: exit 1', () => {
      const w = world();
      const proj = path.join(w.base, 'proj');
      mkdirSync(proj);
      const id = identity(proj);
      const noPath = handStore(w.root, { ...id, dev: '1' }, '');
      const noRecord = handStore(w.root, { ...id, dev: '2' }, undefined);
      const invalid = handStore(w.root, { ...id, dev: '3' }, undefined);
      writeFileSync(path.join(invalid, 'target.json'), 'not json');
      const replaced = `${handStore(w.root, { ...id, dev: '4' }, proj)}.replaced-1764000000000-abcd1234`;
      renameSync(replaced.replace(/\.replaced-.*$/, ''), replaced);
      const link = path.join(w.root, `${id.dev}-${id.ino}-7`);
      symlinkSync(proj, link);

      const r = backups(w);
      expect(r.status, r.stderr).toBe(1);
      expect(blockOf(r.stdout, noPath)).toContain('  state:    not used by a known directory: its target.json names no path');
      expect(blockOf(r.stdout, noRecord)).toContain('  state:    no target.json, so it does not say which directory it is for.');
      expect(blockOf(r.stdout, invalid)).toContain(
        '  state:    not used: its target.json is not a record HackMyAgent wrote, so rollback refuses it',
      );
      expect(blockOf(r.stdout, replaced)).toContain('  state:    not used: a later --fix moved it aside');
      expect(blockOf(r.stdout, link)).toBe([
        link,
        '  state:    not a store: a symbolic link or a file stands at a store\'s name, and rollback refuses it',
        '  delete:   review it and remove it by hand if it is not yours',
      ].join('\n'));
      expect(r.stdout).toContain('5 backup stores: 0 in use, 5 not in use.');
      expect(existsSync(proj), 'the symbolic link\'s target was touched').toBe(true);
    });

    it.skipIf(isRoot)('a store that could not be read: exit 2', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const [store] = storesUnder(w.root);
      chmodSync(store, 0o000);
      try {
        const r = backups(w);
        expect(r.status, r.stderr).toBe(2);
        expect(blockOf(r.stdout, store)).toContain('  state:    could not be read: its run directories could not be listed');
        expect(r.stdout).toContain('1 backup store: 0 in use, 0 not in use, 1 could not be read.');
      } finally {
        chmodSync(store, 0o700);
      }
    });
  });

  describe('the reused-identity cell against a mutant that ignores the creation time', () => {
    it('goes red: the mutant calls the store in use and exits 0', () => {
      const marks = realpathSync.native(tempDir('hma-1035-mutant-'));
      const applied = path.join(marks, 'applied');
      const preload = path.join(marks, 'birth-time-less.cjs');
      // Rewrites the one comparison of the creation time in the built
      // listing, in memory, as the module is loaded: the files under dist/
      // are not touched. It records that the rewrite happened, so a build in
      // which the line reads differently fails this cell instead of passing
      // it with no mutant in place.
      writeFileSync(preload, [
        "'use strict';",
        "const Module = require('module');",
        "const fs = require('fs');",
        "const path = require('path');",
        "const target = path.join('dist', 'store', 'archive-store.js');",
        "const from = 'if (current.birthtimeNs !== key.birthtimeNs) {';",
        'const compile = Module.prototype._compile;',
        'Module.prototype._compile = function (content, filename) {',
        '  if (filename.endsWith(target) && content.includes(from)) {',
        "    content = content.replace(from, 'if (false) {');",
        `    fs.writeFileSync(${JSON.stringify(applied)}, filename);`,
        '  }',
        '  return compile.call(this, content, filename);',
        '};',
        '',
      ].join('\n'));

      const failures = reusedIdentityCell(world(), ['--require', preload]);
      expect(existsSync(applied), 'the mutant was not applied: the built listing no longer has the line it rewrites').toBe(true);
      expect(readFileSync(applied, 'utf-8')).toBe(path.join(path.dirname(BUILT_CLI), 'store', 'archive-store.js'));
      expect(failures).toContain('exit 0, not 1');
      expect(failures.some((f) => f.startsWith('the store is reported in use:'))).toBe(true);
    });
  });

  describe('render safety', () => {
    it('a store root a shell would execute: the delete command offered deletes the store and nothing else', () => {
      const w = world();
      const root = path.join(w.base, `r $(touch PWNED) \`touch PWNED\`; touch PWNED & 'q' "d" \\ *`);
      const env = { HMA_BACKUP_HOME: root };
      const proj = fixableProject(w, 'proj $(touch PWNED)');
      fix(w, proj, env);
      const [store] = storesUnder(root);

      const r = backups(w, [], env);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain(`Backup stores under ${root} (set by HMA_BACKUP_HOME):`);
      for (const line of r.stdout.split('\n')) expect(line).not.toMatch(CONTROL);
      const deletes = r.stdout.split('\n').filter((l) => l.startsWith('  delete:   '));
      expect(deletes).toHaveLength(1);
      const command = deletes[0].slice('  delete:   '.length);
      expect(command.startsWith('rm -rf ')).toBe(true);
      expect(pwnedUnder(w.base), 'the CLI ran a name it printed').toEqual([]);

      const sh = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8', cwd: w.cwd, env: { PATH: process.env.PATH ?? '' } });
      expect(sh.status, sh.stderr).toBe(0);
      expect(existsSync(store), 'the delete command did not delete the store').toBe(false);
      expect(statSync(root).isDirectory(), 'the delete command removed the root').toBe(true);
      expect(liveConfig(proj)).toContain('${GITHUB_TOKEN}');
      expect(pwnedUnder(w.base), 'the delete command ran part of a name').toEqual([]);
      expect(existsSync(path.join(process.cwd(), 'PWNED'))).toBe(false);
    });

    it('a store root with terminal control characters: none reaches the output, and no delete command is offered', () => {
      const w = world();
      const root = path.join(w.base, 'r\u001b[2J\u001b]0;title\u0007\r\nfake line\u202e $(touch PWNED)');
      const env = { HMA_BACKUP_HOME: root };
      const proj = fixableProject(w);
      fix(w, proj, env);
      const [store] = storesUnder(root);

      const r = backups(w, [], env);
      expect(r.status, r.stderr).toBe(0);
      const lines = r.stdout.replace(/\n$/, '').split('\n');
      for (const line of lines) expect(line).not.toMatch(CONTROL);
      expect(lines.filter((l) => l.startsWith('fake line'))).toEqual([]);
      expect(r.stdout).not.toContain('rm -rf');
      expect(r.stdout).toContain('  delete:   remove that directory by hand');
      expect(r.stdout).toContain('1 backup store: 1 in use, 0 not in use.');
      expect(existsSync(store)).toBe(true);
      expect(pwnedUnder(w.base)).toEqual([]);
    });
  });

  describe('exit codes', () => {
    it('0 with every store in use, 1 once one is not, 2 once one could not be read', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      expect(backups(w).status).toBe(0);

      const gone = handStore(w.root, { ...identity(proj), dev: '1' }, path.join(w.base, 'gone'));
      expect(backups(w).status).toBe(1);

      if (isRoot) return; // root reads a directory whatever its mode
      chmodSync(gone, 0o000);
      try {
        expect(backups(w).status).toBe(2);
      } finally {
        chmodSync(gone, 0o700);
      }
    });

    it('2 for `backups delete <store dir>`, with the store directory intact', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const [store] = storesUnder(w.root);
      const before = snapshot(store);

      const r = backups(w, ['delete', store]);
      expect(r.status).toBe(2);
      expect(r.stderr).toContain(`Error: backups takes no arguments or options, and was given: delete ${store}`);
      expect(r.stdout).toBe('');
      expect(snapshot(store)).toEqual(before);
      expect(backups(w).status, 'the refused delete changed what the listing says').toBe(0);
    });

    it('2 for an option, and 0 again once it is dropped', () => {
      const w = world();
      const proj = fixableProject(w);
      fix(w, proj);
      const r = backups(w, ['--delete']);
      expect(r.status).toBe(2);
      expect(r.stdout).toBe('');
      expect(backups(w).status).toBe(0);
    });
  });
});
