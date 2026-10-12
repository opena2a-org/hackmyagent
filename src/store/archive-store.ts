/**
 * Where `--fix` keeps the pre-fix copies of the files it changes (#376).
 *
 * `--fix` used to write them into the tree it was fixing, as
 * `<target>/.hackmyagent-backup/<stamp>/`, and every later scan of that tree
 * reported them: the plaintext credential the fix had just redacted from the
 * live file, and a second record of every finding the fix could not repair.
 * Measured on a tree with an execute-what-the-user-pastes instruction, a
 * wildcard permission grant and a token in `config.json`: 59/100 for the live
 * files, 35/100 on `--fix` and on every scan after it, until the user deleted
 * the directory by hand.
 *
 * Archives now live outside the tree, under a per-user state directory:
 *
 *   <store root>/<dev>-<ino>-<birth>/target.json   which directory this store is for
 *   <store root>/<dev>-<ino>-<birth>/<stamp>/      one `--fix` run's copies
 *
 *   store root: $HMA_BACKUP_HOME, else $OPENA2A_HOME/backups, else ~/.opena2a/backups
 *
 * The store root has to be an absolute path. A relative one names a different
 * directory from each working directory, so `--fix` run from one place would
 * write backups that `rollback` run from another could not find. It is
 * refused wherever it comes from, and the refusal names the variable.
 *
 * keyed by the target directory's filesystem identity, never by its path. A
 * path is a string the scanned tree can spell (#317), and it changes when the
 * user moves or renames the project, which would leave `rollback` unable to
 * find the archive it needs. The identity follows a move or a rename on the
 * same filesystem and a symlink to the target, and two trees with the same
 * name have different identities.
 *
 * A device and an inode number alone are not an identity: delete a directory
 * and the filesystem may give its inode number to the next one. Measured on
 * Linux (ext4), the next directory created took a removed directory's inode
 * number in 20 of 20 tries. The key therefore carries the target's birth time
 * (`<birth>`, nanoseconds since the epoch), so such a directory gets a store of
 * its own: `rollback` there finds no backup, and the removed directory's store
 * is left where it is. `target.json` records the birth time too, and a store
 * whose record names another birth time is not used for its target. A
 * filesystem that reports no birth time gives 0, and there the device and inode
 * number alone decide.
 *
 * The store root is created 0700, each target's store 0700, and `target.json`
 * 0600; the scanner creates each run directory 0700 and each copy 0600. The
 * copies are plaintext, and the files they were taken from could hold a
 * credential the run then redacted. A directory that already exists at
 * `$HMA_BACKUP_HOME` is the user's: it keeps the mode it has, and only what
 * HackMyAgent creates inside it is made private.
 *
 * Nothing here is reached by a scan: the store is outside the scanned tree, and
 * a store that would sit inside it (`secure --fix ~`) is refused, so that run
 * detects only.
 */

import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { userStoreRoot, realpathOfExistingPrefix } from './project-store';

/** The record naming the directory a target store belongs to. */
const TARGET_RECORD = 'target.json';
/** No record HackMyAgent writes comes near this; a larger one is not ours. */
const MAX_RECORD_BYTES = 64 * 1024;

export type ArchiveStoreErrorCode =
  | 'HMA-BACKUP-SYMLINK'
  | 'HMA-BACKUP-NOT-DIR'
  | 'HMA-BACKUP-INSIDE-TREE'
  | 'HMA-BACKUP-RELATIVE-ROOT';

/** The environment variable the store root is read from. `HOME` stands for the home directory when neither override is set. */
export type BackupStoreRootVariable = 'HMA_BACKUP_HOME' | 'OPENA2A_HOME' | 'HOME';

/** Which variable decides the store root in this environment. An empty value counts as unset. */
export function backupStoreRootVariable(): BackupStoreRootVariable {
  if (process.env.HMA_BACKUP_HOME) return 'HMA_BACKUP_HOME';
  if (process.env.OPENA2A_HOME) return 'OPENA2A_HOME';
  return 'HOME';
}

/** Why a store root that is not absolute is refused, naming the variable it came from. */
function relativeRootReason(variable: BackupStoreRootVariable): string {
  return `${variable} is not an absolute path, and the backup store is derived from it. A relative path names a `
    + 'different directory from each working directory, so backups written from one could not be found from another';
}

/**
 * `$HMA_BACKUP_HOME`, else `<user store>/backups`. Not created. Throws
 * `HMA-BACKUP-RELATIVE-ROOT` when the result is not an absolute path: nothing
 * is resolved against the working directory, so nothing is created under it.
 */
export function backupStoreRoot(): string {
  const root = process.env.HMA_BACKUP_HOME || path.join(userStoreRoot(), 'backups');
  if (!path.isAbsolute(root)) {
    throw storeError('HMA-BACKUP-RELATIVE-ROOT', root, `${relativeRootReason(backupStoreRootVariable())}.`);
  }
  return root;
}

/**
 * The store root as a lookup searches it (#1043): its real path, with whatever
 * part does not exist yet appended as spelled. This is the prefix a
 * `Backup created:` path starts with. Throws as `backupStoreRoot` does.
 */
export function searchedBackupStoreRoot(): string {
  return realpathOfExistingPrefix(backupStoreRoot());
}

/**
 * How the store root was chosen, in the words a report prints beside it
 * (#1043). One helper, so every line that names the root says the same thing
 * about where it came from.
 */
export function backupStoreRootSource(): string {
  const variable = backupStoreRootVariable();
  return variable === 'HOME' ? 'the default, under your home directory' : `set by ${variable}`;
}

interface TargetIdentity {
  dev: string;
  ino: string;
  /** Nanoseconds since the epoch, as a decimal string; `'0'` when the filesystem reports none. */
  birthtimeNs: string;
}

interface TargetRecord {
  schemaVersion: 1;
  dev: string;
  ino: string;
  birthtimeNs: string;
  /** Where the target was the last time a `--fix` run wrote here. For the user's reference only. */
  lastKnownPath: string;
  createdAt: string;
}

/**
 * What a lookup found for a target.
 *
 * `other-directory`: a store exists under this target's key and its record
 * names a directory created at another time. It is never used as this
 * target's store, and it is never removed.
 */
export type ArchiveStoreLookup =
  | { kind: 'store'; dir: string; lastKnownPath?: string }
  | { kind: 'none' }
  | { kind: 'other-directory'; dir: string; lastKnownPath?: string }
  | { kind: 'unknown'; dir?: string; reason: string };

function storeError(code: ArchiveStoreErrorCode, dir: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  err.path = dir;
  return err;
}

/** Bigint stat: an inode number can exceed 2^53 on some filesystems, and a rounded one names another directory. */
async function targetIdentity(targetReal: string): Promise<TargetIdentity> {
  const st = await fs.stat(targetReal, { bigint: true });
  return { dev: st.dev.toString(), ino: st.ino.toString(), birthtimeNs: st.birthtimeNs.toString() };
}

/** `<dev>-<ino>-<birth>`: the birth time keeps a directory that reuses a removed one's inode number out of its store. */
function storeDirFor(id: TargetIdentity): string {
  return path.join(searchedBackupStoreRoot(), `${id.dev}-${id.ino}-${id.birthtimeNs}`);
}

/**
 * Where `targetDir`'s store is or would be, without creating or reading
 * anything in it. For callers that name the location, such as a disclosure
 * line or a test that has to look inside it.
 */
export async function archiveStoreDirFor(targetDir: string): Promise<string> {
  return storeDirFor(await targetIdentity(fsSync.realpathSync.native(targetDir)));
}

/** A zero on either side means the filesystem gave no birth time, so the check cannot be made. */
function sameBirth(recorded: string, current: string): boolean {
  return recorded === '0' || current === '0' || recorded === current;
}

function isWithin(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

type RecordRead = { kind: 'absent' } | { kind: 'invalid' } | { kind: 'record'; record: TargetRecord };

/** Only ENOENT is absence. Any other errno throws: an unreadable record proves nothing about whose store this is. */
async function readRecord(dir: string): Promise<RecordRead> {
  const file = path.join(dir, TARGET_RECORD);
  let st: fsSync.Stats;
  try {
    st = await fs.lstat(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return { kind: 'absent' };
    throw err;
  }
  if (!st.isFile() || st.size > MAX_RECORD_BYTES) return { kind: 'invalid' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(await fs.readFile(file, 'utf-8'));
  } catch (err) {
    if (err instanceof SyntaxError) return { kind: 'invalid' };
    throw err;
  }
  const r = parsed as Partial<TargetRecord> | null;
  if (!r || typeof r !== 'object' || typeof r.dev !== 'string' || typeof r.ino !== 'string'
    || typeof r.birthtimeNs !== 'string') {
    return { kind: 'invalid' };
  }
  return {
    kind: 'record',
    record: {
      schemaVersion: 1,
      dev: r.dev,
      ino: r.ino,
      birthtimeNs: r.birthtimeNs,
      lastKnownPath: typeof r.lastKnownPath === 'string' ? r.lastKnownPath : '',
      createdAt: typeof r.createdAt === 'string' ? r.createdAt : '',
    },
  };
}

/** Written to a temporary name and renamed, so a reader never sees half a record. */
async function writeRecord(dir: string, record: TargetRecord): Promise<void> {
  const tmp = path.join(dir, `.${TARGET_RECORD}.${crypto.randomBytes(4).toString('hex')}`);
  await fs.writeFile(tmp, JSON.stringify(record, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await fs.rename(tmp, path.join(dir, TARGET_RECORD));
}

/**
 * Create `dir` 0700 if absent, and prove it is a real directory either way.
 * The mode is re-applied to an existing one; a directory this user cannot
 * chmod keeps its mode, which is not a reason to refuse a backup.
 *
 * `keepExistingMode` is for the one directory the user can name, the store
 * root under `HMA_BACKUP_HOME`: when it already exists its mode is theirs and
 * is left as found. It is still created 0700 when it is absent.
 */
async function ensurePrivateDir(dir: string, opts: { keepExistingMode?: boolean } = {}): Promise<void> {
  let existed = false;
  try {
    await fs.mkdir(dir, { mode: 0o700 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
    existed = true;
  }
  const st = await fs.lstat(dir);
  if (st.isSymbolicLink()) {
    throw storeError('HMA-BACKUP-SYMLINK', dir, `${dir} is a symbolic link, and backups are not written through a link.`);
  }
  if (!st.isDirectory()) {
    throw storeError('HMA-BACKUP-NOT-DIR', dir, `${dir} exists and is not a directory, so backups cannot be stored there.`);
  }
  if (existed && opts.keepExistingMode) return;
  try { await fs.chmod(dir, 0o700); } catch { /* not ours to change, or a filesystem without mode bits */ }
}

/**
 * The directory this target's `--fix` runs store their archives under, created
 * and recorded. Returns its real path. Throws when no store can be used, which
 * the scanner turns into a detect-only run (FIX-BACKUP-FAILED).
 *
 * A store under this key whose record HackMyAgent did not write, or names a
 * directory created at another time, is moved aside to
 * `<key>.replaced-<time>-<random>`, never deleted and never adopted: its runs
 * may be another directory's files, and restoring them here would put that
 * directory's content over this one.
 */
export async function prepareArchiveStore(targetDir: string): Promise<string> {
  const targetReal = fsSync.realpathSync.native(targetDir);
  const id = await targetIdentity(targetReal);
  const dir = storeDirFor(id);
  if (isWithin(dir, targetReal)) {
    throw storeError(
      'HMA-BACKUP-INSIDE-TREE',
      dir,
      `The backup store ${dir} would sit inside the directory being fixed, where every later scan would report its copies.`,
    );
  }

  // Ancestors keep their default mode; only the store root and below are
  // private. A root the user named with HMA_BACKUP_HOME and that already
  // exists keeps its mode: a shared or group-readable directory they chose is
  // not ours to close. `<user store>/backups` is ours, and stays 0700.
  //
  // The one exception is `~/.opena2a` when neither override is set: the
  // OpenA2A user config creates it 0700, and a `--fix` that runs first used to
  // create it at the default mode instead (`drwxrwxrwx` under umask 000). It
  // is created 0700 when absent, as the user config does; an existing one keeps
  // the mode it has.
  const root = path.dirname(dir);
  const variable = backupStoreRootVariable();
  await fs.mkdir(path.dirname(root), variable === 'HOME' ? { recursive: true, mode: 0o700 } : { recursive: true });
  await ensurePrivateDir(root, { keepExistingMode: variable === 'HMA_BACKUP_HOME' });
  await ensurePrivateDir(dir);

  let found = await readRecord(dir);
  if (found.kind === 'invalid' || (found.kind === 'record' && !sameBirth(found.record.birthtimeNs, id.birthtimeNs))) {
    const aside = `${dir}.replaced-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    await fs.rename(dir, aside);
    await ensurePrivateDir(dir);
    found = { kind: 'absent' };
  }

  if (found.kind === 'absent') {
    await writeRecord(dir, {
      schemaVersion: 1,
      dev: id.dev,
      ino: id.ino,
      birthtimeNs: id.birthtimeNs,
      lastKnownPath: targetReal,
      createdAt: new Date().toISOString(),
    });
  } else if (found.record.lastKnownPath !== targetReal) {
    await writeRecord(dir, { ...found.record, lastKnownPath: targetReal });
  }

  return fsSync.realpathSync.native(dir);
}

/**
 * The store for `targetDir`, without creating anything. Never throws: a
 * question the filesystem would not answer is `unknown`, with the reason.
 */
export async function findArchiveStore(targetDir: string): Promise<ArchiveStoreLookup> {
  let id: TargetIdentity;
  try {
    id = await targetIdentity(fsSync.realpathSync.native(targetDir));
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'none' }
      : { kind: 'unknown', reason: 'the directory could not be identified on the filesystem' };
  }
  let dir: string;
  try {
    dir = storeDirFor(id);
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'HMA-BACKUP-RELATIVE-ROOT'
      ? { kind: 'unknown', reason: relativeRootReason(backupStoreRootVariable()) }
      : { kind: 'unknown', reason: 'the backup store location could not be resolved' };
  }
  try {
    const st = await fs.lstat(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      return { kind: 'unknown', dir, reason: 'it is not a directory HackMyAgent created' };
    }
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'none' }
      : { kind: 'unknown', dir, reason: 'the filesystem would not say what it is' };
  }
  let found: RecordRead;
  try {
    found = await readRecord(dir);
  } catch {
    return { kind: 'unknown', dir, reason: `its ${TARGET_RECORD} could not be read` };
  }
  if (found.kind === 'invalid') {
    return { kind: 'unknown', dir, reason: `its ${TARGET_RECORD} is not a record HackMyAgent wrote` };
  }
  if (found.kind === 'record' && !sameBirth(found.record.birthtimeNs, id.birthtimeNs)) {
    return { kind: 'other-directory', dir, lastKnownPath: found.record.lastKnownPath || undefined };
  }
  return {
    kind: 'store',
    dir,
    lastKnownPath: found.kind === 'record' ? found.record.lastKnownPath || undefined : undefined,
  };
}

/** The run directories in a store: every entry that is a directory and not dot-named. */
export async function listArchiveRuns(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory() && !e.name.startsWith('.')).map((e) => e.name);
}

/**
 * The store for `targetDir` and how many runs it holds, for the line `secure`
 * prints about it. Undefined when there is no store or it holds no run, and on
 * any failure: the line is information, never a gate.
 */
export async function describeArchiveStore(targetDir: string): Promise<{ dir: string; runs: number } | undefined> {
  const found = await findArchiveStore(targetDir);
  if (found.kind !== 'store') return undefined;
  try {
    const runs = (await listArchiveRuns(found.dir)).length;
    return runs > 0 ? { dir: found.dir, runs } : undefined;
  } catch {
    return undefined;
  }
}
