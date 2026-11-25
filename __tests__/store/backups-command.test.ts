/**
 * #1035 (part 1): `hackmyagent backups` lists every backup store `--fix` kept
 * under the root `rollback` searches, with the state of each, and changes
 * nothing.
 *
 * Before it, `secure` named only the store of the directory it scanned. A
 * store whose directory was moved, deleted or given another creation time
 * stayed on disk, holding plaintext pre-fix copies, and no command named it.
 *
 * The in-process cells build each state by hand under a throwaway
 * `HMA_BACKUP_HOME`: a store is `<dev>-<ino>-<birth>/target.json`, so a state
 * is a relation between that name, that record and the directory at the path
 * the record names. The spawned cells run the built CLI for the exit codes,
 * the refusal of arguments and the read-only property.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, statSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { listBackupStores, prepareArchiveStore, type BackupStoreEntry } from '../../src/store/archive-store';
import { renderBackupsReport } from '../../src/store/backups-report';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const SOURCE = 'set by HMA_BACKUP_HOME';
const isRoot = process.getuid?.() === 0;

let savedHome: string | undefined;
let root: string;

beforeEach(() => {
  savedHome = process.env.HMA_BACKUP_HOME;
  root = path.join(realpathSync.native(tempDir('hma-1035-')), 'store-root');
  process.env.HMA_BACKUP_HOME = root;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HMA_BACKUP_HOME;
  else process.env.HMA_BACKUP_HOME = savedHome;
});

/** A directory to write a store for, by its real path. */
function project(): string {
  return realpathSync.native(tempDir('hma-1035-proj-'));
}

function identity(dir: string): { dev: string; ino: string; birthtimeNs: string } {
  const st = statSync(dir, { bigint: true });
  return { dev: st.dev.toString(), ino: st.ino.toString(), birthtimeNs: st.birthtimeNs.toString() };
}

/** A store under `key`, with a record naming `lastKnownPath`, and `runs` run directories. */
function handStore(
  key: { dev: string; ino: string; birthtimeNs: string },
  lastKnownPath: string | undefined,
  runs = 1,
): string {
  const dir = path.join(root, `${key.dev}-${key.ino}-${key.birthtimeNs}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (lastKnownPath !== undefined) {
    writeFileSync(path.join(dir, 'target.json'), JSON.stringify({
      schemaVersion: 1, ...key, lastKnownPath, createdAt: '2026-11-25T00:00:00.000Z',
    }));
  }
  for (let i = 0; i < runs; i += 1) mkdirSync(path.join(dir, `2026-11-25-00000000${i}-000-abcdef0${i}`));
  return dir;
}

async function only(): Promise<BackupStoreEntry> {
  const listing = await listBackupStores();
  expect(listing.kind).toBe('listed');
  if (listing.kind !== 'listed') throw new Error('unreachable');
  expect(listing.stores).toHaveLength(1);
  return listing.stores[0];
}

describe('#1035 listBackupStores: one state per store, from its name, its record and the directory it names', () => {
  it('no root: nothing to list, and the root is not created', async () => {
    expect(await listBackupStores()).toEqual({ kind: 'no-root', root });
    expect(() => statSync(root)).toThrow();
  });

  it('in-use: the store --fix wrote for a directory that is still where it was', async () => {
    const proj = project();
    const dir = await prepareArchiveStore(proj);
    mkdirSync(path.join(dir, '2026-11-25-000000000-000-abcdef01'));
    const e = await only();
    expect(e).toMatchObject({ dir, state: 'in-use', lastKnownPath: proj, runs: 1, deletable: true });
  });

  it('directory-gone: nothing is at the path the record names', async () => {
    const proj = project();
    const key = identity(proj);
    handStore(key, path.join(proj, 'moved-away'));
    expect(await only()).toMatchObject({ state: 'directory-gone', runs: 1 });
  });

  it('other-directory: another directory is at the path the record names', async () => {
    const proj = project();
    const other = project();
    handStore(identity(proj), other);
    expect(await only()).toMatchObject({ state: 'other-directory', lastKnownPath: other });
  });

  it('other-birth: the directory there has the store\'s device and inode number and another birth time', async () => {
    const proj = project();
    const id = identity(proj);
    if (id.birthtimeNs === '0') return; // a filesystem with no birth time keys every store at 0
    const later = { ...id, birthtimeNs: (BigInt(id.birthtimeNs) + 1_000n).toString() };
    handStore(later, proj);
    expect(await only()).toMatchObject({ state: 'other-birth', targetBornEarlier: true });
  });

  it('other-birth: a directory with a later birth time than the key is not known to be the store\'s', async () => {
    const proj = project();
    const id = identity(proj);
    if (id.birthtimeNs === '0') return;
    const earlier = { ...id, birthtimeNs: (BigInt(id.birthtimeNs) - 1_000n).toString() };
    handStore(earlier, proj);
    expect(await only()).toMatchObject({ state: 'other-birth', targetBornEarlier: false });
  });

  it('no-record, no-path, invalid-record and a record naming another key', async () => {
    const proj = project();
    const id = identity(proj);
    handStore({ ...id, dev: '1' }, undefined, 2);
    handStore({ ...id, dev: '2' }, '');
    const garbage = handStore({ ...id, dev: '3' }, undefined);
    writeFileSync(path.join(garbage, 'target.json'), 'not json');
    const mismatched = handStore({ ...id, dev: '4' }, proj);
    const rec = JSON.parse(readFileSync(path.join(mismatched, 'target.json'), 'utf-8'));
    writeFileSync(path.join(mismatched, 'target.json'), JSON.stringify({ ...rec, ino: '999' }));

    const listing = await listBackupStores();
    if (listing.kind !== 'listed') throw new Error(`listed expected, got ${listing.kind}`);
    expect(listing.stores.map((s) => [path.basename(s.dir).split('-')[0], s.state])).toEqual([
      ['1', 'no-record'], ['2', 'no-path'], ['3', 'invalid-record'], ['4', 'invalid-record'],
    ]);
    expect(listing.stores[0].runs).toBe(2);
  });

  it('replaced, not-a-directory, and entries that are not stores', async () => {
    const proj = project();
    const id = identity(proj);
    const store = handStore(id, proj);
    renameSync(store, `${store}.replaced-1764000000000-abcd1234`);
    symlinkSync(proj, path.join(root, `${id.dev}-${id.ino}-7`));
    writeFileSync(path.join(root, 'notes.txt'), 'mine\n');
    mkdirSync(path.join(root, 'something-else'));

    const listing = await listBackupStores();
    if (listing.kind !== 'listed') throw new Error(`listed expected, got ${listing.kind}`);
    expect(listing.stores.map((s) => s.state).sort()).toEqual(['not-a-directory', 'replaced']);
    expect(listing.stores.find((s) => s.state === 'replaced')?.lastKnownPath).toBe(proj);
    expect(listing.stores.find((s) => s.state === 'not-a-directory')?.deletable).toBe(false);
    expect(listing.otherEntries).toBe(2);
  });

  it.skipIf(isRoot || process.platform === 'win32')('unknown: a store whose runs cannot be listed', async () => {
    const proj = project();
    const dir = handStore(identity(proj), proj);
    chmodSync(dir, 0o000);
    try {
      expect(await only()).toMatchObject({ state: 'unknown', reason: 'its run directories could not be listed' });
    } finally {
      chmodSync(dir, 0o700);
    }
  });

  it.skipIf(isRoot || process.platform === 'win32')('unknown: a root that cannot be listed', async () => {
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o000);
    try {
      expect(await listBackupStores()).toMatchObject({ kind: 'unknown', root, reason: 'it could not be listed' });
    } finally {
      chmodSync(root, 0o700);
    }
  });

  it.skipIf(process.platform === 'win32')('a root other accounts can write: every store is reported as refused', async () => {
    const proj = project();
    await prepareArchiveStore(proj);
    chmodSync(root, 0o777);
    const listing = await listBackupStores();
    if (listing.kind !== 'listed') throw new Error(`listed expected, got ${listing.kind}`);
    expect(listing.sharedRoot).toMatch(/can be written by other user accounts/);
    const report = renderBackupsReport(listing, { rootSource: SOURCE });
    expect(report.exitCode).toBe(1);
    expect(report.lines.join('\n')).toContain('1 backup store: 0 in use, 1 not in use.');
  });
});

describe('#1035 renderBackupsReport: header, one block per store, footer, and the exit code', () => {
  const entry = (over: Partial<BackupStoreEntry>): BackupStoreEntry => ({
    dir: '/r/1-2-3', state: 'in-use', lastKnownPath: '/p', runs: 1, deletable: true, ...over,
  });

  it('exits 0 when every store is in use, 1 when one is not, 2 when one could not be read', () => {
    const listed = (stores: BackupStoreEntry[]) => ({ kind: 'listed' as const, root: '/r', stores, otherEntries: 0 });
    expect(renderBackupsReport(listed([entry({})]), { rootSource: SOURCE }).exitCode).toBe(0);
    expect(renderBackupsReport(listed([]), { rootSource: SOURCE }).exitCode).toBe(0);
    expect(renderBackupsReport(listed([entry({}), entry({ state: 'directory-gone' })]), { rootSource: SOURCE }).exitCode).toBe(1);
    expect(renderBackupsReport(
      listed([entry({ state: 'directory-gone' }), entry({ state: 'unknown', reason: 'x' })]),
      { rootSource: SOURCE },
    ).exitCode).toBe(2);
    expect(renderBackupsReport({ kind: 'no-root', root: '/r' }, { rootSource: SOURCE }).exitCode).toBe(0);
    expect(renderBackupsReport({ kind: 'unknown', root: '/r', reason: 'x' }, { rootSource: SOURCE }).exitCode).toBe(2);
  });

  it('prints the header, a block per store with its delete command, and the footer', () => {
    const report = renderBackupsReport({
      kind: 'listed',
      root: '/r',
      otherEntries: 1,
      stores: [entry({}), entry({ dir: '/r/1-2-4', state: 'directory-gone', runs: 0 })],
    }, { rootSource: SOURCE });
    expect(report.lines).toEqual([
      'Backup stores under /r (set by HMA_BACKUP_HOME):',
      '',
      '/r/1-2-3',
      '  state:    in use: rollback run in /p restores from it, and has nothing to restore once it is deleted',
      '  backups:  1 --fix run',
      '  delete:   rm -rf /r/1-2-3',
      '',
      '/r/1-2-4',
      expect.stringMatching(/^ {2}state: {4}not used: nothing is at \/p, /),
      '  backups:  none',
      '  delete:   rm -rf /r/1-2-4',
      '',
      '2 backup stores: 1 in use, 1 not in use.',
      '1 other entry under the root is not a backup store and is not listed.',
      'Nothing was written or deleted.',
    ]);
  });

  it('offers no delete command for what this account does not own, or a path it cannot name truthfully', () => {
    const report = renderBackupsReport({
      kind: 'listed',
      root: '/r',
      otherEntries: 0,
      stores: [
        entry({ state: 'not-owned', reason: 'it belongs to another user account', deletable: false, runs: undefined }),
        entry({ dir: '/r/1-2-5', state: 'not-a-directory', deletable: false, runs: undefined }),
        entry({ dir: '/r/x\ny', state: 'no-record' }),
        entry({ dir: "/r/it's here", state: 'no-record' }),
      ],
    }, { rootSource: SOURCE });
    const text = report.lines.join('\n');
    expect(text.match(/rm -rf/g)).toHaveLength(1);
    expect(text).toContain("rm -rf '/r/it'\\''s here'");
    expect(text).toContain('no command to delete it is offered');
    expect(text).toContain('review it and remove it by hand');
    expect(text).toContain('the name above is an escaped rendering');
    for (const line of report.lines) expect(line).not.toMatch(/[\u0000-\u001f\u007f]/);
  });
});

/** Every path under `dir` with its mode, size, mtime and bytes: what a write, chmod or delete would change. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      const p = path.join(d, name);
      const st = statSync(p);
      out.push(`${path.relative(dir, p)} ${st.mode} ${st.size} ${st.mtimeMs} ${st.ino}`
        + (st.isFile() ? ` ${readFileSync(p, 'base64')}` : ''));
      if (st.isDirectory()) walk(p);
    }
  };
  walk(dir);
  return out;
}

describe('#1035 hackmyagent backups, spawned', () => {
  beforeAll(assertDistFresh);

  function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
    const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, NO_COLOR: '1', HOME: tempDir('hma-1035-home-'), HMA_BACKUP_HOME: root },
    });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  it('exits 0 with no store root, and does not create it', () => {
    const r = run(['backups']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('No backup store root at');
    expect(() => statSync(root)).toThrow();
  });

  it('exits 0 when every store is in use, 1 when one is not, and changes nothing', async () => {
    const proj = project();
    const dir = await prepareArchiveStore(proj);
    mkdirSync(path.join(dir, '2026-11-25-000000000-000-abcdef01'));
    writeFileSync(path.join(dir, '2026-11-25-000000000-000-abcdef01', 'config.json'), '{}\n');

    const before = snapshot(root);
    const ok = run(['backups']);
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout).toContain('1 backup store: 1 in use, 0 not in use.');
    expect(ok.stdout).toContain(`rm -rf ${dir}`);
    expect(snapshot(root)).toEqual(before);

    const gone = handStore({ ...identity(proj), dev: '1' }, path.join(proj, 'gone'));
    const before2 = snapshot(root);
    const bad = run(['backups']);
    expect(bad.status, bad.stderr).toBe(1);
    expect(bad.stdout).toContain(gone);
    expect(bad.stdout).toMatch(/2 backup stores: 1 in use, 1 not in use\./);
    expect(snapshot(root)).toEqual(before2);
  });

  it.skipIf(isRoot || process.platform === 'win32')('exits 2 when a store could not be read', () => {
    const dir = handStore({ dev: '1', ino: '2', birthtimeNs: '3' }, '/nowhere');
    chmodSync(dir, 0o000);
    try {
      const r = run(['backups']);
      expect(r.status).toBe(2);
      expect(r.stdout).toContain('could not be read: its run directories could not be listed');
    } finally {
      chmodSync(dir, 0o700);
    }
  });

  it('refuses an argument or an option with exit 2, and lists nothing', () => {
    const proj = project();
    handStore(identity(proj), proj);
    for (const args of [['backups', proj], ['backups', '--json'], ['backups', 'a', '--all']]) {
      const r = run(args);
      expect(r.status, args.join(' ')).toBe(2);
      expect(r.stderr).toMatch(/^Error: backups takes no arguments or options/m);
      expect(r.stdout).not.toContain('Backup stores under');
    }
  });
});
