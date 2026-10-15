/**
 * The `secure --fix` backup store and `rollback`.
 *
 * Before any fix runs, `createBackup` creates this run's directory in the
 * per-user backup store, outside the scanned tree, and writes its manifest.
 * Every fix write then goes through `ensureBackupCovers`, which copies the file
 * it is about to change, and every `chmod` a fix makes goes through
 * `ensureModeRecorded`, which records the mode it is about to change.
 * `rollback` puts the newest run's copies and modes back and removes the files
 * that run created, when their bytes are still the bytes HackMyAgent wrote.
 *
 * `HardeningScanner` owns the run state, one `ScanRun` per scan, and hands the
 * store a host that reads it. So a store answers for the scan running in the
 * calling async context, as the scanner's own methods do.
 */
import { fs } from './tracked-fs';
// `realpath.native` exists only on the callback and sync APIs, and `rollback`
// needs it for the store directory: the JS implementation does not
// canonicalize case.
import * as fsSync from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import {
  isPathWithinDirectory as containIsPathWithinDirectory,
  resolveInsideTree as containResolveInsideTree,
  type ResolveOutcome,
  type ResolveRefusal,
  readStaysInsideTree,
} from './contain';
import type { WithheldLink } from './coverage-ledger';
import { escapeForDisplay, escapePathForDisplay } from '../ui/display-safe';
import { citationTarget } from '../ui/shell-quote';
import {
  prepareArchiveStore, findArchiveStore, listArchiveRuns, backupStoreRootSource, searchedBackupStoreRoot,
  ownedByCurrentUser, findOtherBirthStores, OTHER_BIRTH_STORE_MEANING, type OtherBirthStore,
} from '../store/archive-store';

/**
 * The directory `--fix` writes its backups into. Named once because two
 * different walks have to agree about it, and they did not: the gateway walk
 * tested the entry NAME at every level while the sensitive-artifact walk
 * tested a root-anchored PREFIX (#302).
 */
export const BACKUP_DIR_NAME = '.hackmyagent-backup';

/**
 * Backup manifest format version. v1 (pre-0.25.1) wrote `createdFiles` as a
 * plain string array holding every backup candidate that happened to be
 * absent when the backup was taken, and rollback unlinked all of them — so a
 * file the user wrote between `--fix` and `rollback` was deleted as though
 * HMA had generated it, while SOUL.md (not a candidate at all) survived a
 * rollback that claimed everything had been reverted (#262).
 */
const BACKUP_MANIFEST_VERSION = 2;

/** A file a fix stage actually created, with the hash of what it wrote. */
export interface CreatedFileRecord {
  /** Path relative to the scan target. */
  path: string;
  /** sha256 of the generated content, at the moment it was recorded. */
  sha256: string;
}

/** v2 backup manifest. v1 manifests are read defensively — see readManifest. */
export interface BackupManifest {
  version?: number;
  /**
   * Files that existed before the fix and were copied into the backup.
   *
   * #1039 — copied when a fix is about to write them, never before. A run
   * written by an earlier build lists every candidate that existed, changed or
   * not, and is restored as it lists them.
   */
  existingFiles: string[];
  /**
   * Each `existingFiles` entry's mode when it was copied, as `stat.mode &
   * 0o777` of the source (#376). The copy itself is narrowed to `0600`, and
   * `copyFile` gives the restored file the copy's mode, so without this a
   * rollback left a `0755` script and a `0644` config at `0600`.
   *
   * Honored only for a run in the backup store. A run inside the scanned tree
   * (`.hackmyagent-backup/`, 0.33.2 and earlier) ignores it even when present:
   * no release wrote it there, so one found there was written by the tree,
   * and those copies already carry their original mode. A missing entry or a
   * value that is not an integer from 0 to 4095 restores at the copy's mode.
   * A set-user-id, set-group-id or sticky bit is never restored (#1039).
   */
  existingFileModes?: Record<string, number>;
  /**
   * #1039 — files whose mode a fix changed and whose content no fix had
   * changed, with the mode each had before (`stat.mode & 0o777`). The
   * permissions fix records the entry before its `chmod`, so the run holds no
   * copy of a `.env` whose only change was its mode. A later write to the same
   * file moves the entry into `existingFiles`, carrying this mode.
   *
   * Honored only for a run in the backup store, like `existingFileModes`.
   */
  modeOnlyFiles?: Record<string, number>;
  /**
   * Backup candidates observed missing WHEN THE BACKUP WAS TAKEN. Candidates
   * only, not claims: nothing here is known to have been written.
   */
  absentAtBackup: string[];
  /**
   * Paths proven missing immediately BEFORE a fix wrote them (#300/#304).
   *
   * Kept apart from `absentAtBackup` because the two are different evidence
   * and `recordCreatedFiles` turns both into a rollback-time `unlink`. Folding
   * write-time absences into the backup-time list silently falsified the
   * safety argument stated at that call site — that every entry was observed
   * missing at backup time — which is the one property making the delete safe.
   */
  absentAtFixWrite?: string[];
  /** Files a fix stage created, hashed so rollback can verify before deleting. */
  createdFiles: CreatedFileRecord[];
  /** v1 `createdFiles` entries, preserved verbatim so rollback can report them. */
  legacyCreatedFiles?: string[];
}

/** What a rollback actually did, so the CLI never overstates it. */
export interface RollbackReport {
  /** Files restored from the backup copy. */
  restored: string[];
  /**
   * #1039 — files whose mode was set back from a mode-only entry, with that
   * mode. Their content was never copied because no fix changed it.
   */
  modesRestored: Array<{ path: string; mode: number }>;
  /** Generated files removed (content hash still matched). */
  removed: string[];
  /** Generated files left in place because the user edited them since. */
  keptModified: string[];
  /** Files a pre-0.25.1 manifest listed with no hash to verify against. */
  keptUnverifiable: string[];
  /**
   * Files the manifest listed that could NOT be put back, with the reason
   * (#327). A rollback with any of these has not completed, so the caller must
   * report this rather than claim a clean revert.
   *
   * #338/#346 — `backupHoldsCopy` says whether the backup actually still holds a
   * copy of THIS entry. It is the fact the retention decision is made on, and
   * the fact the header states; both used to be asserted unconditionally of
   * every entry, and for a manifest naming a file the backup never held, both
   * were false.
   */
  unrestored: Array<{ path: string; reason: string; backupHoldsCopy: boolean }>;
  /**
   * Files the manifest listed as GENERATED that this run could not act on
   * (#342).
   *
   * #327's stated property is that a rollback either puts every listed file back
   * or says which ones it could not, and only `existingFiles` got that channel.
   * A `createdFiles` entry whose destination would not resolve was dropped with a
   * bare `continue`, and the legacy loop did the same: measured on a `SOUL.md`
   * that is a symlink, `[+] Rollback complete / removed 0 generated files`, exit
   * 0, the file still on disk and the backup consumed.
   *
   * Reported, never retained on: the backup holds no copy of a generated file, so
   * keeping the directory buys nothing and would feed the #338 wedge.
   */
  unremoved: Array<{ path: string; reason: string }>;
  /**
   * Backups this run passed over because they could not be used at all — a
   * symlink, a non-directory, an unreadable or implausible manifest (#338).
   *
   * Selection is a GUESS at a name the scanned tree can write, so it must be
   * able to try the next candidate. These are reported, never deleted: HMA
   * could not read them, so it cannot know they hold nothing.
   */
  skippedBackups: Array<{ name: string; reason: string }>;
  /**
   * Candidates that listed files and put none of them back.
   *
   * A backup that promised entries and delivered nothing is not this run's
   * backup, whatever the reason — and the reason is always something the scanned
   * tree arranged, at one end or the other. It is KEPT (it may hold bytes nobody
   * can read yet), reported, and passed over, so one forged directory cannot
   * stand in front of the real backup for ever.
   */
  barrenBackups: Array<{ name: string; listed: number }>;
  /**
   * How many further backup directories sit behind the one this run used
   * (#338). Reported when a rollback does not complete, so a user staring at a
   * retained directory is told that dealing with it uncovers another.
   */
  backupsBehind: number;
  /**
   * Where the backup was left when it still holds a copy of something that
   * could not be restored. Absent when the backup held nothing worth keeping,
   * which is the case that consumes it.
   */
  backupRetainedAt?: string;
  /** Which backup directory under the base this run actually used. */
  backupUsed?: string;
  /**
   * Where that base is (#376). `store` is the per-user backup store `--fix`
   * writes to; `in-tree` is a `.hackmyagent-backup` an earlier version wrote
   * inside the target, used only when rollback finds no run for it in the
   * store. The report names the in-tree case, because restoring from a
   * directory the scanned tree could have written is worth knowing about.
   */
  backupSource?: 'store' | 'in-tree';
  /** The resolved base directory the run directory was taken from. */
  backupBase?: string;
  /**
   * Stores kept under the target's device and inode number and another birth
   * time, which an `in-tree` run did not use (#1049). The report names them
   * and does not say the store held no backup: one of them holds the target's
   * newer backups when its reported birth time changed after a `--fix`.
   */
  otherBirthStores?: Array<{ dir: string; lastKnownPath?: string }>;
  /**
   * The backup this run finished with and could not delete.
   *
   * Its own channel, not `backupRetainedAt`: that one means "kept on purpose,
   * because it still holds a copy", it is rendered only inside the
   * `unrestored` block, and a run with nothing unrestored would have set it and
   * printed nothing — a backup left on disk with no line saying so.
   */
  backupRemovalFailed?: { path: string; reason: string };
}

/** How `rollback` cites the command in the next steps of an error it throws (#1043). */
export interface RollbackOptions {
  /** The command prefix, as `scan` takes it. Default `hackmyagent`. */
  cliName?: string;
  /** The directory as the user typed it. Default: the directory `rollback` was given. */
  typedDir?: string;
}

/**
 * `rollback` restored nothing, and `message` is the block that says why
 * (#1043): what happened, then that nothing was restored, then the next steps,
 * one per line and indented two spaces.
 *
 * Every path is display-escaped before it goes into a line, so the message
 * splits into lines only at the block's own line breaks, and a caller prints it
 * line by line. A raw path never goes in: a directory name can hold a newline
 * followed by text that reads as a next step of ours.
 */
export class RollbackNothingRestoredError extends Error {
  constructor(lines: readonly string[]) {
    super(lines.join('\n'));
    this.name = 'RollbackNothingRestoredError';
  }
}

// `ResolveRefusal` / `ResolveOutcome` / `resolveInsideTree` moved to
// `./contain` (#270). The write side needs the identical containment property
// and had none, and two implementations of "is this path inside the tree" is
// exactly how that asymmetry arose.

/** Why one manifest entry could not be put back. */
type RestoreRefusal =
  | ResolveRefusal
  | 'source-outside-backup'
  | 'source-unreadable'
  | 'source-resolves-outside-backup'
  | 'source-not-regular-file'
  | 'source-unexaminable'
  | 'write-failed';

/**
 * One sentence per cause, each true of that cause and of nothing else.
 *
 * Written as a total record rather than a `switch` with a default, so adding a
 * refusal without giving it a sentence is a compile error rather than a silent
 * fallback to whichever sentence was nearest.
 */
const RESTORE_REFUSAL_REASONS: Record<RestoreRefusal, string> = {
  'escapes-tree': 'the manifest entry points outside the scanned directory',
  'parent-unresolvable': 'the directory it belongs in could not be resolved',
  'parent-outside-tree': 'a directory on the way to it leads outside the scanned directory',
  'leaf-is-link': 'a symbolic link stands where the file should be',
  'leaf-link-dangling': 'it is a symbolic link that points at nothing',
  'leaf-link-outside-tree': 'it is a symbolic link that points outside the scanned directory',
  'leaf-unexaminable': 'the filesystem would not say what is currently at that path',
  'source-outside-backup': 'the manifest entry points outside the backup',
  'source-unreadable': 'the backup holds no readable copy of it',
  'source-resolves-outside-backup': 'the copy in the backup resolves outside the backup',
  'source-not-regular-file': 'the copy in the backup is not a regular file',
  'source-unexaminable': 'the copy in the backup could not be examined',
  'write-failed': 'writing it back failed',
};

/**
 * The largest `.manifest.json` `rollback` will parse: the 10 MB the scanner
 * puts on a file it reads, a size no real manifest reaches.
 */
const MAX_MANIFEST_SIZE = 10 * 1024 * 1024;

/**
 * A directory named by its filesystem IDENTITY rather than by any spelling of
 * its path.
 *
 * Four rounds of this subsystem's guards were strings that DESCRIBE the backup
 * directory — a `\`-folded path (#304), a directory name (#305), a manifest
 * shape (#309), a case-sensitive `path.resolve` prefix compare (#317) — and
 * every round the attacker changed the string without changing the directory.
 * `dev`+`ino` is the directory itself: it cannot be respelled by case folding
 * on a case-insensitive filesystem, by a symlink, by Unicode normalization, or
 * by a `..` that cancels out.
 */
export interface FsIdentity {
  dev: number;
  ino: number;
}

/**
 * The identity of what a path reaches, or why it could not be taken.
 *
 * #333 — `identityOf` used to return `null` for every failure, and `null` means
 * "not our backup" to both callers. For the DETECTION walk that is fail-closed:
 * the directory gets scanned, so nothing is hidden. For the WRITE gate it is
 * fail-OPEN — `isInsideOwnBackup` returning false there means ALLOW THE WRITE —
 * so any `EACCES`, `ELOOP`, `EIO` or `EMFILE` on an ancestor `stat` during a
 * `--fix` run left HackMyAgent free to rewrite its own backup, with only the
 * name check standing in the way: the string this whole change argues cannot be
 * trusted.
 *
 * Only ENOENT proves absence. Everything else proves nothing, and "I could not
 * check" must not become "it is not ours" — the same inference as #313, and as
 * the `resolveInsideTree` fail-open fixed earlier in this stack.
 */
export type IdentityProbe =
  | { kind: 'identity'; id: FsIdentity }
  /** Proven absent: nothing is there. */
  | { kind: 'absent' }
  /** The filesystem refused to answer. Establishes nothing in either direction. */
  | { kind: 'unknown' };

/** `stat`, not `lstat`: the identity wanted is the directory a path REACHES. */
export async function identityOf(p: string): Promise<IdentityProbe> {
  try {
    const st = await fs.stat(p);
    return { kind: 'identity', id: { dev: st.dev, ino: st.ino } };
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'absent' }
      : { kind: 'unknown' };
  }
}

/** Fails closed: a missing identity on either side is never a match. */
export function sameIdentity(a: FsIdentity | null | undefined, b: FsIdentity | null | undefined): boolean {
  return !!a && !!b && a.dev === b.dev && a.ino === b.ino;
}

/** The identity if one could be taken, else undefined — for the callers that only need a match. */
export function identityOrUndefined(probe: IdentityProbe): FsIdentity | undefined {
  return probe.kind === 'identity' ? probe.id : undefined;
}

/**
 * A backup-setup failure that carries WHY, machine-readably.
 *
 * `FIX-BACKUP-FAILED` used to report `code` from `err.name`, which is `Error` for
 * anything that is not an errno — so a refusal HMA decided on its own arrived at
 * the user as a bare "Backup failed (Error)" under guidance that listed only
 * permission causes and a fix line saying "make the target writable". For a
 * symlinked backup base that advice is wrong: making it writable changes nothing.
 * The code lets the finding name the real cause and the matching remedy.
 *
 * The refusals about the store directory itself (`HMA-BACKUP-SYMLINK`,
 * `HMA-BACKUP-NOT-DIR`, `HMA-BACKUP-INSIDE-TREE`, `HMA-BACKUP-RELATIVE-ROOT`) are raised by
 * `src/store/archive-store.ts` with the same `code` field (#376), and so are the
 * refusals of a store another user account owns or could replace
 * (`HMA-BACKUP-NOT-OWNED`, `HMA-BACKUP-SHARED-ROOT`, #1051).
 */
type BackupSetupCode = 'HMA-BACKUP-NO-NEW-DIR' | 'HMA-BACKUP-VANISHED' | 'HMA-BACKUP-UNIDENTIFIED';

function backupSetupError(code: BackupSetupCode, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

/**
 * The identity of a just-created backup directory, or the right refusal.
 *
 * #347.3 — this used to be `identityOrUndefined(...)` followed by `if (!ident)`,
 * which collapses the three-valued probe back into two and throws away exactly
 * the distinction #333 added it for. An EACCES, ELOOP or EIO on the directory
 * `mkdir` had just returned was reported as `HMA-BACKUP-VANISHED — disappeared
 * immediately after being created`, a claim about the filesystem that only
 * ENOENT supports, sending the user to look for a race that is not there.
 *
 * A named function rather than three lines inline, because the window between
 * `mkdir` and `stat` is not something a test can hold open: the decision is
 * observable here, and observing it is the point.
 */
export function backupIdentityOrThrow(probe: IdentityProbe, backupDir: string): FsIdentity {
  if (probe.kind === 'identity') return probe.id;
  if (probe.kind === 'absent') {
    throw backupSetupError(
      'HMA-BACKUP-VANISHED',
      `Backup directory ${backupDir} disappeared immediately after being created.`,
    );
  }
  throw backupSetupError(
    'HMA-BACKUP-UNIDENTIFIED',
    `Backup directory ${backupDir} was created, but the filesystem would not describe it, `
    + 'so HackMyAgent cannot tell its own backup apart from the files it is about to fix.',
  );
}

/**
 * The ordering field of a backup directory name: exactly three characters,
 * always.
 *
 * #347.6 — `createRunBackupDir` added `attempt` (up to 7) to a sequence already
 * capped at 998 and then padded, so a 999th same-millisecond sibling produced a
 * FOUR-character field, breaking both the sort invariant the name exists for and
 * the three-character parse that reads it back. `nextStampSequence` keeps its own
 * cap; what was missing is a clamp AFTER the addition, which is the only place
 * that holds.
 *
 * Exported so the invariant can be asserted against THIS expression rather than
 * against a copy of it in a test — the whole width range is unreachable through
 * `createRunBackupDir`, which needs 999 directories in one millisecond plus two
 * `EEXIST` collisions on an unpredictable component.
 */
export function stampSequenceField(seq: number, attempt: number): string {
  return String(Math.min(seq + attempt, 999)).padStart(3, '0');
}

/** This run's backup, from the moment `createBackup` made it. */
export interface BackupContext {
  backupDir: string;
  /**
   * The backup directory's `dev`+`ino`. Carried separately from the path
   * because the path is what four rounds of attackers respelled (#317).
   */
  backupIdent: FsIdentity;
  targetDir: string;
  covered: Set<string>;
  /** Paths with a mode-only entry in this run's manifest (#1039). */
  modeRecorded: Set<string>;
}

/** The backup state of one scan run. The scanner's `ScanRun` carries it. */
export interface BackupRunState {
  /**
   * Backup context for the current `--fix` run, or undefined when no backup
   * was taken (detect-only, dry-run, or a `createBackup` failure that already
   * downgraded the run). `applyFixWrite` refuses to write without it — see
   * `ensureBackupCovers`. Starts undefined on every run and is only ever set
   * once a backup actually exists, so one run's backup cannot authorise
   * another run's writes (#300).
   */
  backupContext: BackupContext | undefined;
  /**
   * Target-relative paths the last `createBackup` already accounted for, in
   * either manifest list. Seeds `backupContext.covered` so the static
   * candidates are not re-copied one at a time.
   */
  lastBackupCovered: string[];
  /** Identity of the directory the last `createBackup` created. See #317. */
  lastBackupIdent: FsIdentity | undefined;
  /**
   * Candidates the last `createBackup` refused to copy because they resolve
   * outside the scanned tree. The refusal is a policy skip that must be
   * ANNOUNCED, never silent: the caller that renders withheld links merges
   * these with the scan-side records (`backupWithheldLinks`).
   */
  lastBackupWithheldLinks: WithheldLink[];
}

/** What the store needs from the scanner that runs it. */
export interface BackupStoreHost {
  /** The backup state of the scan running in the calling async context. */
  run(): BackupRunState;
  /** The skill files under `dir`, which the skill fixes rewrite in place. */
  findSkillFiles(dir: string): Promise<string[]>;
  /** The static backup candidates, target-relative. */
  readonly candidateFiles: readonly string[];
}

/**
 * The backup store and `rollback` of one scanner instance. Run state is read
 * and written through `host.run()` on every access, so two scans running at
 * once on one instance each see their own backup.
 */
export class BackupStore {
  constructor(private readonly host: BackupStoreHost) {}

  // The run state, read and written through the host's current run. Each
  // field is documented on `BackupRunState`.
  private get backupContext(): BackupContext | undefined { return this.host.run().backupContext; }
  private set backupContext(v: BackupContext | undefined) { this.host.run().backupContext = v; }
  private get lastBackupCovered(): string[] { return this.host.run().lastBackupCovered; }
  private set lastBackupCovered(v: string[]) { this.host.run().lastBackupCovered = v; }
  private get lastBackupIdent(): FsIdentity | undefined { return this.host.run().lastBackupIdent; }
  private set lastBackupIdent(v: FsIdentity | undefined) { this.host.run().lastBackupIdent = v; }
  private get lastBackupWithheldLinks(): WithheldLink[] { return this.host.run().lastBackupWithheldLinks; }
  private set lastBackupWithheldLinks(v: WithheldLink[]) { this.host.run().lastBackupWithheldLinks = v; }

  private isPathWithinDirectory(filePath: string, directory: string): boolean {
    return containIsPathWithinDirectory(filePath, directory);
  }

  private findSkillFiles(dir: string): Promise<string[]> {
    return this.host.findSkillFiles(dir);
  }

  /**
   * Resolve a relative path to a real location inside the tree, or say why it
   * does not stay there. See `./contain`, which the fix-write side and
   * `SoulScanner.hardenSoul` use too.
   */
  private async resolveInsideTree(
    targetReal: string,
    rel: string,
    opts: { followLeafLink: boolean },
  ): Promise<ResolveOutcome> {
    return containResolveInsideTree(targetReal, rel, opts);
  }

  /**
   * Guarantee the backup can undo a write to `filePath` before it happens.
   * Returns false when it cannot, and the caller must then not write (#300).
   *
   * The backup candidate set used to be a static, root-relative list
   * (`BACKUP_FILES`), predicted ahead of the scan. Every widening of
   * DETECTION therefore silently widened the set of files `--fix` rewrites
   * WITHOUT widening the set it can restore. #292 widened CRED-001 to
   * config-shaped files at any depth and this is what shipped:
   *
   *   before   config/production.json + src/config.json  = a live token
   *   --fix    both -> ${GITHUB_TOKEN}
   *   backup   holds only package.json
   *   rollback "Restored 1 modified file", exit 0
   *   after    both still redacted, original bytes unrecoverable
   *
   * Irreversible data loss behind an explicit success message. Extending the
   * static list would have closed that one instance and left the next
   * widening — #298 is already queued — to reopen it, so the coverage is
   * derived from the WRITE instead of predicted before it: whatever a fix is
   * about to touch is captured now, at the one choke point every fix write
   * already goes through.
   *
   * Fail-safe in every direction. No backup context, a path outside the
   * scanned tree, or a failed copy all return false, and the write is
   * abandoned and reported as FIX-WRITE-FAILED — the user keeps their bytes
   * and is told the fix did not land, which is the recoverable outcome. A
   * file that does not exist yet is a creation, not an overwrite: nothing to
   * copy, so it is recorded as an absent candidate and left to
   * `recordCreatedFiles`, which hash-verifies before rollback removes it.
   *
   * #1039 — this is the only place an existing file is copied. `createBackup`
   * used to copy every candidate before any check ran, so a `.env` no fix
   * touched sat in plaintext in every run. A file is copied here, when a fix is
   * about to write it, and the content is the same: every earlier write to it
   * in this run came through here and was copied first.
   */
  /**
   * Copy one file into this run's backup, owner-only (#376).
   *
   * `copyFile` gives the copy the source's mode, so a `0644` config holding a
   * token produced a world-readable plaintext copy. The copy is narrowed to
   * `0600` and any directory created for it is `0700`. A filesystem that
   * refuses the `chmod` keeps the copy: the run directory above it is
   * already `0700`, and losing the copy would make the fix unrecoverable.
   *
   * Returns the source's mode (`stat.mode & 0o777`, following links as
   * `copyFile` does), read before the copy is narrowed, so the manifest can
   * record it and `rollback` can put it back (`existingFileModes`). Undefined
   * when the source would not say; the copy is kept either way. A source that
   * is missing still throws from `copyFile`, before any `stat`. The
   * set-user-id, set-group-id and sticky bits are not recorded (#1039).
   */
  private async copyIntoBackup(sourcePath: string, destPath: string): Promise<number | undefined> {
    await fs.mkdir(path.dirname(destPath), { recursive: true, mode: 0o700 });
    await fs.copyFile(sourcePath, destPath);
    let sourceMode: number | undefined;
    try { sourceMode = (await fs.stat(sourcePath)).mode & 0o777; } catch { /* restored at the copy's mode */ }
    try { await fs.chmod(destPath, 0o600); } catch { /* no mode bits here; the 0700 run directory still confines it */ }
    return sourceMode;
  }

  async ensureBackupCovers(filePath: string): Promise<boolean> {
    const ctx = this.backupContext;
    if (!ctx) return false;

    const rel = this.toTargetRelativePath(filePath, ctx.targetDir);
    if (!rel) return false; // escapes the scanned tree — not ours to rewrite
    if (ctx.covered.has(rel)) return true;

    // `copyFile` follows symlinks, matching `createBackup`: the fix sites
    // write THROUGH a link, so the bytes at the far end are what has to be
    // recoverable. See the symlink note in `createBackup`.
    //
    // Copy FROM `filePath` — the path this write will actually land on — and
    // never from a path rebuilt out of `rel`. `rel` is a normalized
    // description of `filePath`, and re-deriving the source from it was #304:
    // the guard protected a path that was not the one being written.
    let existed = true;
    let sourceMode: number | undefined;
    try {
      sourceMode = await this.copyIntoBackup(filePath, path.join(ctx.backupDir, rel));
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') return false;
      // ENOENT is overloaded here and only ONE of its meanings is a creation.
      // It is also raised for a dangling symlink (the entry exists and the fix
      // writes THROUGH it), for a backup directory that vanished mid-run, and
      // for any source that resolves somewhere unexpected. So absence is
      // PROVEN against the real path rather than inferred from an errno —
      // inferring it is what made the guard authorise the write it exists to
      // gate. `lstat`, not `stat`: a dangling symlink is an entry that exists,
      // so it is not a creation, and it has no recoverable copy — fail safe.
      if (!(await this.isGenuinelyAbsent(filePath))) return false;
      existed = false;
    }

    // Persist before returning: `recordCreatedFiles` re-reads this file from
    // disk, and `rollback` is a separate process. An in-memory-only update
    // would restore nothing.
    if (!(await this.appendToBackupManifest(ctx.backupDir, rel, existed, sourceMode))) return false;
    ctx.covered.add(rel);
    return true;
  }

  /**
   * Guarantee the backup can undo a `chmod` of `filePath` before it happens
   * (#1039). Returns false when it cannot, and the caller must then not change
   * the mode.
   *
   * A mode change needs the mode, not the content. Copying the whole file to
   * restore one mode is what put a plaintext `.env` in every run whose only
   * change to it was the permissions fix, so a file with no copy in the run gets
   * a mode-only entry (`modeOnlyFiles`) instead. A file this run already copied
   * needs nothing more: its entry carries the mode it had before any fix.
   *
   * The mode is read with `stat`, following a link as `chmod` does, from the
   * path the `chmod` will act on. Fail-safe like `ensureBackupCovers`: no
   * backup context, a path outside the scanned tree, a mode the filesystem
   * will not report, or a manifest that cannot be written all return false.
   */
  async ensureModeRecorded(filePath: string): Promise<boolean> {
    const ctx = this.backupContext;
    if (!ctx) return false;

    const rel = this.toTargetRelativePath(filePath, ctx.targetDir);
    if (!rel) return false;
    if (ctx.covered.has(rel) || ctx.modeRecorded.has(rel)) return true;

    let mode: number;
    try {
      mode = (await fs.stat(filePath)).mode & 0o777;
    } catch {
      return false;
    }
    if (!(await this.recordModeOnly(ctx.backupDir, rel, mode))) return false;
    ctx.modeRecorded.add(rel);
    return true;
  }

  /**
   * True when this path is inside the backup THIS RUN just created.
   *
   * #309 — the only exclusion left, and the only one that can be justified.
   * Every previous version decided whether to suppress a CRITICAL by reading
   * the scanned tree, which is the attacker's own filesystem:
   *
   *   #292/#302  ancestor directory NAMED `.hackmyagent-backup`
   *              -> the name was a one-word suppression token
   *   #305       name + a `.manifest.json` + a live counterpart
   *              -> the manifest is 70 bytes of JSON with two array keys, and
   *                 "is really a copy" was an EXISTENCE test that never
   *                 compared content. A forged manifest plus a benign decoy at
   *                 the mirrored path restored the bypass exactly: identical
   *                 credential bytes, `.notabackup` 69/100 with the CRITICAL,
   *                 `.hackmyagent-backup` 96/100 and silent. Two variants
   *                 needed no decoy at all — a dangling symlink, and an
   *                 ENOTDIR counterpart where the errno was read as "exists".
   *
   * Three rounds, three replacements of one attacker-suppliable token with
   * another. So the property is no longer taken from the tree at all: the run's
   * own `backupDir` is a path HMA chose this run, and nothing in the scanned
   * tree can name it. `createBackup` runs before every check, so without this
   * the same run would report the credential twice — once in the live file and
   * once in the copy HMA made microseconds earlier.
   *
   * A PRE-EXISTING archive is deliberately NOT excluded. After `--fix` the live
   * file holds `${GITHUB_TOKEN}` and the archive holds the only remaining
   * plaintext copy of the secret, so it is not a duplicate of anything —
   * suppressing it would mean hiding a plaintext credential that HMA itself
   * created. It reports, with a fix line that is not `secure --fix` (the write
   * guard refuses to edit archives) and, since #326, one that neither claims HMA
   * created the directory nor offers to delete it.
   *
   * #317 — the fourth round, and the one that made the shape of the class
   * unmistakable. `ctx.backupDir` was compared with `isPathWithinDirectory`, a
   * case-SENSITIVE `path.resolve` prefix compare, so the property was still a
   * STRING describing the directory rather than the directory. One pre-existing
   * `.HACKMYAGENT-BACKUP` on a case-insensitive filesystem (the macOS default)
   * was enough: `mkdir` adopted it, `readdir` returned the original casing, the
   * compare said no, and `--fix` redacted its own backup while `rollback`
   * restored the redaction and reported a clean revert. Measured: the archived
   * copy held `${GITHUB_TOKEN}` 200ms after the original was read.
   *
   * So the question is asked of the FILESYSTEM. `isOwnBackupDir` compares
   * `dev`+`ino`, which no spelling of a path can change.
   *
   * This variant answers the question for a FILE, by walking its ancestors. It
   * costs a `stat` per level, which is affordable at the write gate (a few
   * dozen calls per run) and is not affordable per scanned file — hence the
   * separate primitive the walks use.
   */
  async isInsideOwnBackup(absPath: string): Promise<'yes' | 'no' | 'unknown'> {
    const ctx = this.backupContext;
    if (!ctx) return 'no';
    // Sound positive, no syscall. Only the negative needs the filesystem.
    if (this.isPathWithinDirectory(absPath, ctx.backupDir)) return 'yes';

    let dir = path.dirname(path.resolve(absPath));
    // Bounded: a path with more than 64 components is not something to keep
    // stat-ing, and the answer for anything that deep is "not our backup".
    for (let i = 0; i < 64; i++) {
      const probe = await identityOf(dir);
      if (sameIdentity(identityOrUndefined(probe), ctx.backupIdent)) return 'yes';
      // #333 — an ancestor the filesystem would not describe leaves the question
      // OPEN. Reported as such rather than collapsed into "no", because the
      // caller here is the write gate and "no" there authorises the write.
      if (probe.kind === 'unknown') return 'unknown';
      const parent = path.dirname(dir);
      if (parent === dir) return 'no'; // filesystem root
      dir = parent;
    }
    return 'no';
  }

  /**
   * True when `dirPath` is the backup directory this run created, or lies
   * inside it — decided by identity.
   *
   * This is the primitive the walks use, and it is asked once per directory
   * rather than once per file: a walk that does not descend into the backup
   * cannot produce a path inside it, and one that does (the config walk keeps
   * walking so `keyFiles`/`namedSensitive` semantics stay untouched) carries the
   * answer down its own recursion. That keeps the syscall cost at one `stat`
   * per directory of a `--fix` run, and zero for a detect-only scan.
   *
   * An unreadable directory is deliberately answered "not ours" HERE: the
   * consequence is that the directory is SCANNED, so a credential inside it is
   * still reported. That is the fail-closed direction for detection, and it is
   * the opposite of the direction the write gate needs — see `isInsideOwnBackup`
   * (#333).
   */
  async isOwnBackupDir(dirPath: string): Promise<boolean> {
    const ctx = this.backupContext;
    if (!ctx) return false;
    // A lexical hit is a sound POSITIVE — same spelling, same directory. It is
    // only the NEGATIVE that cannot be trusted, so the syscall is spent only
    // when the cheap compare says no.
    if (this.isPathWithinDirectory(dirPath, ctx.backupDir)) return true;
    return sameIdentity(identityOrUndefined(await identityOf(dirPath)), ctx.backupIdent);
  }

  /**
   * True only when nothing exists at `filePath` — proven, not inferred.
   *
   * This is the sole evidence that a fix write is a CREATION rather than an
   * overwrite, and `recordCreatedFiles` turns that classification into a
   * rollback-time `unlink`. So it fails safe in every unclear direction: an
   * entry that exists is not a creation, and an `lstat` that fails for any
   * other reason (EACCES, ELOOP, EIO) proves nothing, so it is not a creation
   * either. `lstat` deliberately does not follow symlinks — a dangling link
   * is an entry the user put there, and deleting it at rollback would destroy
   * something HMA did not create.
   */
  private async isGenuinelyAbsent(filePath: string): Promise<boolean> {
    try {
      await fs.lstat(filePath);
      return false;
    } catch (err) {
      return (err as NodeJS.ErrnoException)?.code === 'ENOENT';
    }
  }

  /**
   * Add one path to the on-disk manifest, into `existingFiles` (rollback
   * restores it) or `absentAtBackup` (rollback may remove it once
   * `recordCreatedFiles` proves HMA generated it). Returns false if the
   * manifest cannot be read or written, which makes the write unrecoverable
   * and so must abandon it.
   *
   * `sourceMode` is the copied file's mode, recorded in `existingFileModes`
   * in the same write that adds its `existingFiles` entry.
   *
   * #1039 — a file with a mode-only entry was `chmod`ed before this copy, so
   * the copy's source no longer has the mode it started with. The entry's mode
   * is the one recorded, and the entry moves into `existingFiles` in the same
   * write, so `rollback` puts the bytes and the earlier mode back together.
   */
  private async appendToBackupManifest(
    backupDir: string,
    rel: string,
    existed: boolean,
    sourceMode?: number,
  ): Promise<boolean> {
    const manifestPath = path.join(backupDir, '.manifest.json');
    try {
      const manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
      // Write-time absences go in their OWN list. See `absentAtFixWrite`.
      const list = existed
        ? manifest.existingFiles
        : (manifest.absentAtFixWrite ??= []);
      if (!list.includes(rel)) {
        list.push(rel);
        const modeOnly = manifest.modeOnlyFiles && Object.prototype.hasOwnProperty.call(manifest.modeOnlyFiles, rel)
          ? manifest.modeOnlyFiles[rel]
          : undefined;
        const mode = modeOnly ?? sourceMode;
        if (existed && mode !== undefined) (manifest.existingFileModes ??= {})[rel] = mode;
        if (existed && modeOnly !== undefined && manifest.modeOnlyFiles) {
          delete manifest.modeOnlyFiles[rel];
          if (Object.keys(manifest.modeOnlyFiles).length === 0) delete manifest.modeOnlyFiles;
        }
      }
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Add one mode-only entry to the on-disk manifest (#1039). Returns false if
   * the manifest cannot be read or written, which makes the `chmod`
   * unrecoverable and so must abandon it. An entry already recorded keeps the
   * mode it was recorded with: that is the mode before the first change.
   */
  private async recordModeOnly(backupDir: string, rel: string, mode: number): Promise<boolean> {
    const manifestPath = path.join(backupDir, '.manifest.json');
    try {
      const manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
      if (!manifest.existingFiles.includes(rel)) {
        const modes = (manifest.modeOnlyFiles ??= {});
        if (!Object.prototype.hasOwnProperty.call(modes, rel)) modes[rel] = mode;
      }
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Take a backup for a mutation that happens OUTSIDE `scan()` (#271).
   *
   * Standalone `harden-soul` rewrites a governance file — measured at
   * 113 -> 19055 bytes — and took no backup at all, so there was nothing for
   * `rollback` to restore. `rollback` then read whatever manifest a previous
   * `secure --fix` had left and printed `[+] Rollback complete` at exit 0,
   * having never heard of the file that changed.
   *
   * Every other mutation in the product is gated on a recoverable copy. This is
   * the same guarantee for the one command that reached the filesystem without
   * going through `scan()`.
   *
   * Returns the backup directory, or null when no backup could be taken — and a
   * null must abandon the write, exactly as `scan()` skips fixing when
   * `createBackup` throws. Applying a fix with nothing to roll back to is the
   * outcome this whole mechanism exists to prevent.
   */
  async beginExternalBackup(targetDir: string): Promise<string | null> {
    try {
      const backupPath = await this.createBackup(targetDir);
      if (!this.lastBackupIdent) return null;
      this.backupContext = {
        backupDir: backupPath,
        backupIdent: this.lastBackupIdent,
        targetDir,
        covered: new Set(this.lastBackupCovered),
        modeRecorded: new Set(),
      };
      return backupPath;
    } catch {
      return null;
    }
  }

  /**
   * Copy candidates the last backup WITHHELD because they resolve outside the
   * scanned tree, for the caller that renders the run's disclosures.
   * `harden-soul` merges these with the scan-side records — same
   * `WithheldLinkRecord` shape after `withheldLinkRecords`, deduped by `rel`,
   * so one withheld link is one line however many sides refused it.
   */
  backupWithheldLinks(): WithheldLink[] {
    return [...this.lastBackupWithheldLinks];
  }

  /**
   * The guard `secure --fix` hands to `hardenSoul` (#271).
   *
   * `harden-soul` runs AFTER `scan()` returns, from the CLI, on this same
   * instance — the run's backup context is still live, which is what lets the
   * governance write be gated by the same recoverability rule as every fix
   * write inside the scan.
   *
   * Returns false when no recoverable copy could be made, and `hardenSoul` then
   * declines the write rather than modifying a file `rollback` cannot put back.
   * Before this, `BACKUP_FILES` carried a hand-copied subset of the governance
   * names and the other eight were modified with no manifest entry at all.
   */
  async ensureGovernanceBackup(targetDir: string, relPath: string): Promise<boolean> {
    return this.ensureBackupCovers(path.join(targetDir, relPath));
  }

  /**
   * The directory `--fix` stores backups under: this target's store in the
   * per-user backup store, outside the scanned tree (#376). Throws when no
   * store can be used, which degrades the run to detect-only rather than
   * writing somewhere unintended.
   *
   * It used to be `<target>/.hackmyagent-backup`, and every later scan of the
   * tree reported the copies in it. The refusals that location needed — a base
   * that is a symlink out of the tree (#321), something that is not a
   * directory, a base resolving outside the tree — are carried over to the
   * store's own directory, and one is added: a store that would sit inside the
   * tree being fixed (`secure --fix ~`) is refused, because there every later
   * scan would report it again. See `src/store/archive-store.ts`.
   */
  private async prepareBackupRoot(targetDir: string): Promise<string> {
    return prepareArchiveStore(targetDir);
  }

  /**
   * The run's own backup directory, created and PROVEN new.
   *
   * #320 — the stamp was `YYYY-MM-DD-HHMMSS` in UTC and the `mkdir` was
   * `recursive: true`, which silently ADOPTS an existing directory. So the
   * scanned tree could name HMA's own backup by guessing a second, turning a
   * CRITICAL into a silent drop and moving the score UP. Two independent
   * reproductions, kept apart rather than blended (#334):
   *
   *   the #320 report          125 pre-seeded stamps, 126 CRED-001 detect-only
   *                            vs 125 under `--fix`
   *   this stack's own run      90 pre-seeded stamps,  91 CRED-001 detect-only
   *                            vs  90 under `--fix`, score 13 -> 14
   *
   * "Unforgeable by construction" was false either way, and 86,400 empty
   * directories cover a whole day.
   *
   * Two independent properties, either of which suffices:
   *   - a random component the tree cannot predict, and
   *   - a NON-recursive `mkdir`, which fails EEXIST instead of adopting. On a
   *     case-insensitive filesystem EEXIST also fires for a case variant, so a
   *     pre-seeded `.../2026-07-29-120000-AB12CD34` cannot become this run's
   *     backup either.
   *
   * The time-ordered prefix stays: `rollback` selects the latest backup by
   * lexical sort, so the NAME has to sort in creation order.
   *
   * #332 — adding the random suffix broke exactly that, and the comment here
   * asserting the invariant was the only thing left holding it. Two backups
   * created inside one second sorted by random hex: measured at the primitive
   * level, 5 of 6 trials selected the OLDER backup, which leaves run 2's
   * generated files in place, deletes run 1's copies, and lets a second
   * rollback restore already-redacted content — #317's shape again.
   *
   * Two changes, so the ordering component is decided by time and only by time:
   *
   *   - the stamp carries MILLISECONDS. Two `createBackup` calls were measured
   *     2-6ms apart, so seconds were not enough resolution to order them.
   *   - within one millisecond, a fixed-width SEQUENCE derived from what is
   *     already in the base orders the siblings. That is what makes sequential
   *     creation deterministic rather than merely likely.
   *
   * The random component stays (that is #320) but no longer decides anything.
   * Truly concurrent creation in the same millisecond by two processes is still
   * a tie — neither is "later" at that resolution — and the concurrency test
   * covers what matters there: neither run adopts or deletes the other's backup.
   *
   * Names written by earlier versions (`YYYY-MM-DD-HHMMSS-<rand>`) sort BELOW a
   * new name from the same second, since a digit outranks the `-` that follows
   * the seconds field. That is the correct order: the new one is later.
   */
  async createRunBackupDir(baseReal: string): Promise<string> {
    const stamp = new Date()
      .toISOString()
      .slice(0, 23)
      .replace('T', '-')
      .replace(/[:.]/g, '');
    const seq = await this.nextStampSequence(baseReal, stamp);

    let lastErr: unknown;
    for (let attempt = 0; attempt < 8; attempt++) {
      const dir = path.join(
        baseReal,
        `${stamp}-${stampSequenceField(seq, attempt)}`
        + `-${crypto.randomBytes(4).toString('hex')}`,
      );
      try {
        // 0700: the copies are plaintext, and one can hold a credential this
        // run is about to redact from the live file (#376).
        await fs.mkdir(dir, { mode: 0o700 });
        return dir;
      } catch (err) {
        lastErr = err;
        // Anything other than "it already exists" is a real filesystem
        // failure and must degrade the run, not be retried 8 times.
        if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
      }
    }
    throw backupSetupError(
      'HMA-BACKUP-NO-NEW-DIR',
      `Could not create a new backup directory under ${baseReal} after 8 attempts`
      + `${lastErr instanceof Error ? `: ${lastErr.message}` : '.'}`,
    );
  }

  /**
   * The next ordering slot for `stamp`: one past the highest sequence already
   * recorded for that same millisecond in this base.
   *
   * Reading the base is what makes SEQUENTIAL creation deterministic rather than
   * merely probable — run 1 is on disk before run 2 asks. Two processes asking
   * at the same instant can still choose the same slot, which is the tie the
   * millisecond stamp has already declared.
   *
   * Fails to zero: an unreadable base leaves ordering to the millisecond stamp,
   * which is the behaviour without this function at all, and never blocks a
   * backup — this is an ordering aid, not a guard.
   */
  private async nextStampSequence(baseReal: string, stamp: string): Promise<number> {
    try {
      const entries = await fs.readdir(baseReal);
      let highest = -1;
      for (const entry of entries) {
        if (!entry.startsWith(`${stamp}-`)) continue;
        const seq = Number.parseInt(entry.slice(stamp.length + 1, stamp.length + 4), 10);
        if (Number.isFinite(seq) && seq > highest) highest = seq;
      }
      return Math.min(highest + 1, 998);
    } catch {
      return 0;
    }
  }

  /**
   * Create this run's backup directory and its manifest, before any fix runs.
   *
   * #1039 — it copies nothing. It used to copy every candidate that existed,
   * so a run held a plaintext `.env` that no fix had touched. What it does
   * before the fixes is what cannot be done later: prove which candidates are
   * absent (the evidence `recordCreatedFiles` needs before `rollback` may delete
   * a file) and withhold the candidates that resolve outside the tree. A file
   * is copied by `ensureBackupCovers` when a fix is about to write it, and a
   * mode change is recorded by `ensureModeRecorded` before the `chmod`.
   */
  async createBackup(targetDir: string): Promise<string> {
    this.lastBackupWithheldLinks = [];
    const backupDir = await this.createRunBackupDir(await this.prepareBackupRoot(targetDir));

    // The identity of the directory just created, captured once. Every later
    // "is this inside the backup?" question is answered against this rather
    // than against a path string — see `isInsideOwnBackup` (#317).
    //
    // #347.3 — this used to go through `identityOrUndefined`, which collapses
    // the three-valued probe back into two and throws away exactly the
    // distinction #333 added it for. An EACCES, ELOOP or EIO on the directory
    // `mkdir` had just returned was reported as `HMA-BACKUP-VANISHED —
    // disappeared immediately after being created`, which is a claim about the
    // filesystem that only ENOENT supports, and it sent the user looking for a
    // race that is not there.
    this.lastBackupIdent = backupIdentityOrThrow(await identityOf(backupDir), backupDir);

    // Create manifest to track what existed before.
    //
    // `absentAtBackup` is the candidate set, NOT a claim that auto-fix
    // created any of it. Pre-0.25.1 this list was written straight into
    // `createdFiles` and rollback unlinked every entry, so a `package.json`
    // or `CLAUDE.md` the user wrote between `--fix` and `rollback` was
    // deleted as if HMA had generated it (#262). `createdFiles` is now
    // filled in after the fixes run, by recordCreatedFiles(), and carries
    // the content hash of what was actually generated.
    const manifest: BackupManifest = {
      version: BACKUP_MANIFEST_VERSION,
      existingFiles: [],
      absentAtBackup: [],
      createdFiles: [],
    };

    // Account for each candidate (static list + skill + web directory scan)
    const filesToBackup = [...this.host.candidateFiles];

    // Skill files discovered recursively. The SKILL-004 and SKILL-019
    // auto-fixes rewrite skill files in place, and those files were in no
    // backup candidate list — so `rollback` could not
    // restore them while still reporting success. Same defect class as the
    // SOUL.md leftover in #262, found while fixing it.
    try {
      for (const skillFile of await this.findSkillFiles(targetDir)) {
        const rel = path.relative(targetDir, skillFile);
        if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) filesToBackup.push(rel);
      }
    } catch { /* discovery is best-effort; never block a fix run */ }

    // Also discover files in web-served directories that --fix may modify
    const webDirs = ['public', 'static', 'dist', 'build', 'out', 'www', '_site'];
    const webExts = ['.html', '.htm', '.js', '.jsx', '.tsx', '.css', '.py', '.md'];
    for (const webDir of webDirs) {
      const webDirPath = path.join(targetDir, webDir);
      try {
        const entries = await fs.readdir(webDirPath, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isFile() && webExts.some(ext => entry.name.endsWith(ext))) {
            filesToBackup.push(path.join(webDir, entry.name));
          }
        }
      } catch { /* dir doesn't exist */ }
    }

    for (const file of filesToBackup) {
      const sourcePath = path.join(targetDir, file);
      try {
        await fs.access(sourcePath);
        // `access` and `copyFile` both follow symlinks, so an unconfined copy
        // backs a symlinked candidate up by CONTENT: a repo shipping
        // `SOUL.md -> <outside>/SOUL.md` got the link target's bytes copied
        // into `.hackmyagent-backup/`, inside the scanned tree. Skipping the
        // copy SILENTLY was tried and reverted while the fix sites still
        // wrote through links; those writes are refused now
        // (`resolveInsideTree`, `followLeafLink: true`), so this is the
        // separate track the old note promised: every candidate is resolved
        // against the scanned tree, and one that leaves it is WITHHELD — no
        // copy, and a manifest entry in NEITHER list (not restorable, so
        // `existingFiles` would lie; not a creation, so `absentAtBackup`
        // would let rollback delete through it; uncovered, so
        // `ensureBackupCovers` refuses a write through it — the safe
        // direction) — plus a disclosure the caller renders alongside the
        // scan-side withheld links. An in-tree link (`SOUL.md ->
        // docs/SOUL.md`) resolves inside and is still backed up by content.
        //
        // #1039 — a candidate that stays inside is not copied here. It is left
        // uncovered, and `ensureBackupCovers` copies it when a fix is about to
        // write it; a candidate no fix writes is never copied at all.
        const stays = readStaysInsideTree(sourcePath, targetDir);
        if (!stays.ok) {
          this.lastBackupWithheldLinks.push({ rel: file, resolved: stays.resolved, call: 'copyFile' });
        }
      } catch {
        // #313 — absence is PROVEN here, never inferred from the fact that
        // something went wrong. This catch-all collapsed ENOENT-of-target,
        // EACCES, ELOOP, EISDIR, ENOSPC and EMFILE into "the file isn't
        // there", and `absentAtBackup` is the candidate list `recordCreatedFiles`
        // draws from — so anything that merely FAILED to copy became eligible
        // to be reported as HMA-generated and deleted by `rollback`.
        //
        // Measured, on the exact case `isGenuinelyAbsent`'s own docstring
        // describes: a user's `.gitignore -> ./nowhere` dangling symlink landed
        // in `absentAtBackup`, was recorded in `createdFiles`, and `rollback`
        // DELETED it while printing "Rollback complete / removed 1 generated
        // file" — leaving behind the file HMA had actually created through the
        // link. A pre-existing `.gitignore` at mode 0222 took the same route:
        // `access(F_OK)` passes, `copyFile` raises EACCES, and the original was
        // overwritten with no copy anywhere.
        //
        // #304 replaced this inference with an lstat proof in
        // `ensureBackupCovers`, but the identical inference survived here, and
        // because `ctx.covered` is pre-seeded from `absentAtBackup` the proof
        // was never consulted for any of the static candidates.
        //
        // Three outcomes, not two. A path that exists but could not be copied
        // belongs in NEITHER list: it is not restorable, so `existingFiles`
        // would lie, and it is not a creation, so `absentAtBackup` would let
        // rollback delete it. Landing in neither leaves it uncovered, which
        // makes `ensureBackupCovers` refuse the write — the safe direction.
        if (await this.isGenuinelyAbsent(sourcePath)) {
          // Candidate only — a fix stage may create it, and
          // recordCreatedFiles() decides afterwards whether it did.
          manifest.absentAtBackup.push(file);
        }
      }
    }

    // Save manifest
    await fs.writeFile(
      path.join(backupDir, '.manifest.json'),
      JSON.stringify(manifest, null, 2),
      { mode: 0o600 },
    );

    // Normalized so `ensureBackupCovers` compares like with like: the entries
    // above are joined with `path.join`, and `toTargetRelativePath` is what
    // the write path produces (#300). `existingFiles` is empty here (#1039).
    this.lastBackupCovered = [...manifest.existingFiles, ...manifest.absentAtBackup]
      .map((f) => this.toTargetRelativePath(f, targetDir))
      .filter((f): f is string => f !== null);

    return backupDir;
  }

  /**
   * Record what a fix stage actually created, with content hashes, so
   * rollback can remove generated files without guessing (#262).
   *
   * Additive and idempotent: `secure --fix` calls this at the end of scan()
   * for the static fixes, and the CLI calls it again after the governance
   * auto-fix (harden-soul runs after scan() returns and is what generates
   * SOUL.md). Re-recording a path already present is a no-op, so the hash
   * always reflects the first write — the one the user was told about.
   *
   * A candidate is recorded only when it did NOT exist at backup time (a
   * file that existed is copied into the backup when a fix first writes it, and must be restored, never
   * deleted) and exists now. Silent on every failure: this is bookkeeping for
   * a convenience feature and must never break a scan that already succeeded.
   */
  async recordCreatedFiles(
    targetDir: string,
    backupPath: string | undefined,
    candidatePaths: readonly string[],
  ): Promise<void> {
    if (!backupPath || candidatePaths.length === 0) return;

    const manifestPath = path.join(backupPath, '.manifest.json');
    let manifest: BackupManifest;
    try {
      manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
    } catch {
      return;
    }

    // Only a file HMA affirmatively observed to be MISSING — either when the
    // backup was taken, or immediately before a fix wrote it — can be recorded
    // as created. A fixed finding on a file in neither list (not a backup
    // candidate) proves the fix touched it, not that the fix made it, and
    // recording it would let rollback delete a file the user wrote. Fail-safe
    // direction: never delete what we cannot prove we generated, even at the
    // cost of leaving a file behind (which the rollback report then names).
    //
    // Both lists are OBSERVATIONS, never inferences. #304 was an errno being
    // read as an observation: a failed copy meant "absent", so a file that
    // existed could be classified as generated and unlinked at rollback. See
    // `isGenuinelyAbsent`.
    //
    // #313 — that claim was FALSE for `absentAtBackup` when it was written.
    // #304 proved absence in `ensureBackupCovers` but left the identical errno
    // inference in `createBackup`, and since `ctx.covered` is pre-seeded from
    // `absentAtBackup` the new proof was never reached for any of the 25 static
    // candidates. Both producers of both lists now prove it, so the sentence
    // above is true of the whole path rather than of one branch of it.
    const provenAbsent = new Set([
      ...manifest.absentAtBackup,
      ...(manifest.absentAtFixWrite ?? []),
    ]);
    const alreadyRecorded = new Set(manifest.createdFiles.map(c => c.path));
    let changed = false;

    for (const candidate of candidatePaths) {
      const rel = this.toTargetRelativePath(candidate, targetDir);
      if (!rel || !provenAbsent.has(rel) || alreadyRecorded.has(rel)) continue;

      const absolute = path.join(targetDir, rel);
      // Defense in depth: a finding's `file` is data, and this path feeds an
      // unlink at rollback time.
      if (!this.isPathWithinDirectory(absolute, targetDir)) continue;

      try {
        const content = await fs.readFile(absolute);
        manifest.createdFiles.push({
          path: rel,
          sha256: crypto.createHash('sha256').update(content).digest('hex'),
        });
        alreadyRecorded.add(rel);
        changed = true;
      } catch {
        // Not created (or unreadable) — nothing to record.
      }
    }

    if (!changed) return;
    try {
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    } catch {
      // Bookkeeping only.
    }
  }

  /**
   * Normalize a candidate path (absolute or target-relative, either
   * separator) to a target-relative path. Returns null when it escapes the
   * target directory.
   */
  toTargetRelativePath(candidate: string, targetDir: string): string | null {
    // No manual separator rewriting (#304). `\` was folded to `/` here to
    // "handle Windows paths", but `path.join`/`path.relative`/`path.isAbsolute`
    // are already platform-correct — on Windows both separators are separators,
    // and on POSIX `\` is an ordinary filename byte. Rewriting it turned a
    // legal name into a different path: the value became a description of
    // itself that no longer round-trips to the file it names. Everything
    // downstream (the backup copy, the manifest key, the rollback restore, the
    // created-file proof) then operated on that description, so a component
    // containing a `\` was rewritten with no recoverable copy while rollback
    // reported success. Two distinct files could also collide onto one key.
    const cleaned = candidate.replace(/^\.\//, '');
    if (!cleaned) return null;
    const absolute = path.isAbsolute(cleaned) ? cleaned : path.join(targetDir, cleaned);
    const rel = path.relative(targetDir, absolute);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return rel;
  }

  /**
   * Parse a backup manifest, tolerating the v1 shape. In v1 `createdFiles`
   * was a string array of every absent backup candidate — an unverifiable
   * claim, so those entries are quarantined into `legacyCreatedFiles` and
   * never deleted. See BACKUP_MANIFEST_VERSION.
   */
  private parseManifest(raw: string): BackupManifest {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const existingFiles = Array.isArray(parsed.existingFiles)
      ? (parsed.existingFiles as unknown[]).filter((f): f is string => typeof f === 'string')
      : [];
    const rawCreated = Array.isArray(parsed.createdFiles) ? (parsed.createdFiles as unknown[]) : [];

    const createdFiles: CreatedFileRecord[] = [];
    const legacyCreatedFiles: string[] = [];
    for (const entry of rawCreated) {
      if (typeof entry === 'string') {
        legacyCreatedFiles.push(entry);
      } else if (
        entry && typeof entry === 'object' &&
        typeof (entry as CreatedFileRecord).path === 'string' &&
        typeof (entry as CreatedFileRecord).sha256 === 'string'
      ) {
        createdFiles.push(entry as CreatedFileRecord);
      }
    }

    // Kept, not dropped: `appendToBackupManifest` and `recordCreatedFiles`
    // rewrite the manifest from this parsed form, so a parse that left the
    // field out would erase every recorded mode at the next fix-write copy.
    // Only keys that are `existingFiles` entries, with an integer from 0 to
    // 4095 (`chmod`'s range), survive.
    const listed = new Set(existingFiles);
    const modeEntries = (raw: unknown, keep: (rel: string) => boolean): Array<[string, number]> =>
      raw && typeof raw === 'object' && !Array.isArray(raw)
        ? Object.entries(raw as Record<string, unknown>).filter(
          (e): e is [string, number] => keep(e[0]) && Number.isInteger(e[1]) && (e[1] as number) >= 0 && (e[1] as number) <= 0o7777,
        )
        : [];
    const fileModes = modeEntries(parsed.existingFileModes, (rel) => listed.has(rel));
    // #1039 — same rule, for paths with no copy: an entry for a file that also
    // has a copy is dropped, and the copy's own mode is the one that counts.
    const modeOnly = modeEntries(parsed.modeOnlyFiles, (rel) => !listed.has(rel));

    return {
      version: typeof parsed.version === 'number' ? parsed.version : 1,
      existingFiles,
      existingFileModes: fileModes.length > 0 ? Object.fromEntries(fileModes) : undefined,
      modeOnlyFiles: modeOnly.length > 0 ? Object.fromEntries(modeOnly) : undefined,
      absentAtBackup: Array.isArray(parsed.absentAtBackup)
        ? (parsed.absentAtBackup as unknown[]).filter((f): f is string => typeof f === 'string')
        : [],
      absentAtFixWrite: Array.isArray(parsed.absentAtFixWrite)
        ? (parsed.absentAtFixWrite as unknown[]).filter((f): f is string => typeof f === 'string')
        : [],
      createdFiles,
      legacyCreatedFiles: legacyCreatedFiles.length > 0 ? legacyCreatedFiles : undefined,
    };
  }

  /**
   * Copy one manifest entry out of the backup and back into the tree.
   *
   * Both ends are resolved (#318). The source must be a regular file that
   * resolves back inside the backup directory — a symlink there copies
   * out-of-tree CONTENT IN, which is the same defect mirrored and was verified
   * with a link to a file outside the tree landing in it.
   *
   * #327 — returns WHY it did not land, never a bare false. Every one of these
   * refusals leaves a manifest entry unrestored, and an unrestored entry that
   * nothing reports is the harm the containment guards exist to prevent, arrived
   * at from the other side: the user is told the revert is complete while their
   * bytes are only in the backup that is about to be deleted.
   *
   * #338 — and it reports whether the BACKUP still holds a copy of this entry,
   * because that is the fact the retention decision and the report header both
   * depend on and neither was checking it. So the SOURCE is probed first, even
   * for an entry whose destination is refused: "is the copy in there" has an
   * answer in every case, and deciding what to keep on disk from a fact nobody
   * established is what #326 was about.
   */
  private async restoreOneBackupFile(
    backupReal: string,
    targetReal: string,
    rel: string,
    restoreMode?: number,
  ): Promise<{ ok: true } | { ok: false; cause: RestoreRefusal; detail?: string; backupHoldsCopy: boolean }> {
    // ---- Does the backup hold a copy of this entry? ----
    //
    // What the backup HOLDS for this entry, decided by this run's own probe.
    //
    // This started as "nothing there is PROVEN, everything else counts as a
    // copy", on the reasoning that refusing to delete is the fail-safe
    // direction. That was wrong in a way the adversarial pass caught: three of
    // the five refusals are decided by bytes the scanned tree wrote INSIDE the
    // forged backup, so `mkdir X` beside a manifest naming `X` made
    // `backupHoldsCopy` true, the directory was retained, and #338's wedge came
    // straight back — three runs, nothing restored, the real backup never
    // reached. A symlink pointing out of the backup did it too.
    //
    // So the question is the one the retention decision actually needs: is there
    // a REGULAR FILE at the resolved source inside the backup — the thing
    // `restoreOneBackupFile` could have copied out? A directory, a link pointing
    // outside, and an entry the filesystem would not describe are all "no":
    // deleting the backup around them destroys nothing this run could have
    // restored, and keeping it hands the scanned tree a permanent lock on the
    // recovery path. The cost is that an EACCES on a real copy goes with the
    // directory; it was unreadable to the user too, and the alternative is an
    // attacker-controlled denial of recovery.
    let sourceReal: string | null = null;
    let sourceRefusal: RestoreRefusal | null = null;
    const sourcePath = path.join(backupReal, rel);
    if (!this.isPathWithinDirectory(sourcePath, backupReal)) {
      sourceRefusal = 'source-outside-backup';
    } else {
      try {
        const candidate = await fs.realpath(sourcePath);
        if (!this.isPathWithinDirectory(candidate, backupReal)) {
          sourceRefusal = 'source-resolves-outside-backup';
        } else {
          try {
            sourceRefusal = (await fs.lstat(candidate)).isFile() ? null : 'source-not-regular-file';
          } catch {
            sourceRefusal = 'source-unexaminable';
          }
          if (!sourceRefusal) sourceReal = candidate;
        }
      } catch {
        sourceRefusal = 'source-unreadable';
      }
    }
    // `sourceReal` is set only when realpath succeeded, the result is inside the
    // backup, and it is a regular file. That is the whole definition.
    const backupHoldsCopy = sourceReal !== null;

    // ---- Where would it go? ----
    const dest = await this.resolveInsideTree(targetReal, rel, { followLeafLink: true });
    if (!dest.ok) return { ok: false, cause: dest.cause, backupHoldsCopy };
    if (sourceRefusal || !sourceReal) {
      return { ok: false, cause: sourceRefusal ?? 'source-unreadable', backupHoldsCopy };
    }

    try {
      await fs.copyFile(sourceReal, dest.path);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      return { ok: false, cause: 'write-failed', detail: code, backupHoldsCopy };
    }
    // #376 — the copy is 0600 and `copyFile` gave the restored file that mode.
    // The mode recorded when the backup was taken goes back on the same
    // resolved destination, so it has the restore's containment: a link out of
    // the tree was refused above, before either call. A failed `chmod` leaves
    // the file at 0600, which is not a reason to report the restore failed.
    // #1039 — the permission bits only: a recorded set-user-id, set-group-id
    // or sticky bit is never put on a file.
    if (restoreMode !== undefined) {
      try { await fs.chmod(dest.path, restoreMode & 0o777); } catch { /* the bytes are back; the mode stays private */ }
    }
    return { ok: true };
  }

  /**
   * Put one mode-only entry back (#1039): `chmod` the file to the mode it had
   * before the permissions fix. Its content was never copied, because no fix
   * changed it.
   *
   * The destination is resolved the way a restore's is, following an in-tree
   * link as the fix's `chmod` did and refusing one that leaves the tree. Only
   * the permission bits are applied. A file that is no longer there, or whose
   * mode the filesystem refuses to change, is reported, with the mode it should
   * have, so the user can set it by hand.
   */
  private async restoreOneMode(
    targetReal: string,
    rel: string,
    mode: number,
  ): Promise<{ ok: true; mode: number } | { ok: false; reason: string }> {
    const permissions = mode & 0o777;
    const shown = permissions.toString(8).padStart(4, '0');
    const dest = await this.resolveInsideTree(targetReal, rel, { followLeafLink: true });
    if (!dest.ok) return { ok: false, reason: `${RESTORE_REFUSAL_REASONS[dest.cause]}; its mode was ${shown}` };
    try {
      await fs.chmod(dest.path, permissions);
      return { ok: true, mode: permissions };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      return {
        ok: false,
        reason: code === 'ENOENT'
          ? `it is no longer there; its mode was ${shown}`
          : `its mode could not be set back to ${shown}${code ? ` (${code})` : ''}`,
      };
    }
  }

  /**
   * Whether the tree holds a `.hackmyagent-backup` that `rollback` would take
   * a run from (#1049): the checks `rollback` makes on that directory before
   * it uses it, answered and not thrown, so that a caller can say something
   * else when there is none. A directory that cannot be listed counts as
   * holding one, which leaves that failure to `rollback`.
   */
  private async inTreeArchiveHoldsRun(targetReal: string): Promise<boolean> {
    let base: string;
    try {
      const joinedBase = path.join(targetReal, BACKUP_DIR_NAME);
      const baseSt = await fs.lstat(joinedBase);
      if (baseSt.isSymbolicLink() || !baseSt.isDirectory()) return false;
      base = await fs.realpath(joinedBase);
      if (!this.isPathWithinDirectory(base, targetReal)) return false;
    } catch {
      return false;
    }
    try {
      return (await listArchiveRuns(base)).length > 0;
    } catch {
      return true;
    }
  }

  /**
   * Rollback to the most recent backup.
   *
   * Returns what it actually did. A generated file is deleted only when its
   * content hash still matches what HMA wrote, so a SOUL.md the user has
   * since edited is kept, not silently discarded (#262). The caller is
   * expected to report the kept files rather than claim a clean revert.
   */
  async rollback(targetDir: string, opts: RollbackOptions = {}): Promise<RollbackReport> {
    const cliName = escapeForDisplay(opts.cliName ?? 'hackmyagent');

    // Resolved once, and every containment decision below is made against this
    // rather than against the caller's spelling. On macOS `os.tmpdir()` alone
    // makes the two differ (`/var` -> `/private/var`), so a resolved-vs-lexical
    // mismatch is the normal case, not an exotic one.
    let targetReal: string;
    try {
      targetReal = await fs.realpath(targetDir);
    } catch {
      // #1043 — no search ran, so this says neither "No backup found" nor
      // which root or variable a search would have used. It used to send the
      // user to `secure --fix`, which cannot create a directory that is gone.
      throw new RollbackNothingRestoredError([
        `${escapePathForDisplay(targetDir)} does not exist or cannot be accessed, so rollback has nothing to restore into.`,
        'Nothing was restored. The backups of a directory that was deleted stay in its backup store.',
        `  If the path is wrong, run: ${cliName} rollback "\${DIR:?set DIR to the directory to restore}"`,
      ]);
    }

    // #1043 — the directory exists and neither the store nor the tree holds a
    // backup for it. The error names the root that was searched and what chose
    // it, because the commonest cause is a `--fix` run under another
    // HMA_BACKUP_HOME or OPENA2A_HOME: its backup is intact in a root this run
    // never looked at. The old advice, to run `secure --fix` first, took a
    // backup of the already-fixed tree, and the next rollback then reported
    // success without the pre-fix content.
    //
    // The root is prose on the first line and in no command. The one command
    // names the directory, quoted as every citation of a target is, and holds
    // no value read from the environment.
    const noBackupFound = (): RollbackNothingRestoredError => new RollbackNothingRestoredError([
      'No backup found for this directory. None of the backup stores in '
      + `${escapePathForDisplay(searchedBackupStoreRoot())} (${backupStoreRootSource()}) is for it, and it holds no `
      + `${BACKUP_DIR_NAME}/ directory with a backup.`,
      'Nothing was restored.',
      '  If --fix ran with a different HMA_BACKUP_HOME or OPENA2A_HOME, set them as that run did, then run: '
      + `${cliName} rollback ${citationTarget(opts.typedDir ?? targetDir)}`,
      '  If every --fix backup of this directory has already been rolled back, or --fix never ran on it, there is '
      + 'nothing to roll back.',
    ]);

    // #376 — the backups `--fix` writes now are in the per-user store, keyed by
    // this directory's identity, so a moved, renamed or symlinked target finds
    // them. They are consulted FIRST and, when the store holds any run, ONLY:
    // nothing in the scanned tree can create or rename a run there, whereas a
    // tree can ship its own `.hackmyagent-backup/9999-…/` that sorts above every
    // real stamp (#338). Merging the two lists would hand that forged directory
    // the first try at writing into the tree.
    //
    // A store whose record names a directory created at another time is not
    // this directory's backups: refused, named, and left alone. A directory
    // that took a removed directory's inode number does not reach it: the key
    // carries the birth time, so that directory has a store of its own.
    // Deleting the store makes this throw "No backup found" or fall back to an
    // archive an earlier version wrote inside the tree, which the report names.
    // It never makes rollback report success with nothing restored.
    const store = await findArchiveStore(targetReal);
    if (store.kind === 'other-directory') {
      throw new Error(
        `The backup store ${store.dir} has this directory's filesystem identity but was recorded for a `
        + 'directory created at another time'
        + `${store.lastKnownPath ? ` (last seen at ${store.lastKnownPath})` : ''}, so rollback will not restore `
        + 'its files here. If those backups are yours, copy the files back by hand from the run directories inside it.',
      );
    }
    if (store.kind === 'unknown') {
      // With no directory the store could not even be located (a relative
      // HMA_BACKUP_HOME, say). That is refused too, and never read as "the
      // store holds no run": falling back to an archive inside the tree here
      // would give a forged one the first try whenever the store is unknown.
      throw new Error(
        store.dir
          ? `The backup store ${store.dir} for this directory could not be used: ${store.reason}. `
            + 'Nothing was restored. Check that directory, then run rollback again.'
          : `The backup store for this directory could not be located: ${store.reason}. Nothing was restored.`,
      );
    }
    let storeRuns: string[] = [];
    if (store.kind === 'store') {
      try {
        storeRuns = await listArchiveRuns(store.dir);
      } catch {
        throw new Error(
          `The backup store ${store.dir} for this directory could not be listed. Nothing was restored.`,
        );
      }
    }

    // `backupBaseDir` is the RESOLVED base from here on, and every path below is
    // built from it. Comparing a resolved path against a lexically-joined one is
    // the #317 mistake in miniature.
    let backupBaseDir: string;
    let backupSource: 'store' | 'in-tree';
    let otherBirthStores: OtherBirthStore[] = [];
    if (store.kind === 'store' && storeRuns.length > 0) {
      backupBaseDir = fsSync.realpathSync.native(store.dir);
      backupSource = 'store';
    } else {
      // #1049 — no run under this directory's key is not yet "the store holds
      // no backup for it". The key carries the birth time the filesystem
      // reports, and that can change after a `--fix`: on macOS it moves back
      // when the directory's modification time is set earlier (`touch -t`,
      // `rsync -a`, `tar -x`, `cp -p`). The runs are then under the key the
      // directory had when they were taken, and this branch used to restore an
      // older archive from inside the tree, exit 0, and report that the store
      // held none.
      //
      // A store under this device and inode number and another birth time is
      // therefore named, and never restored from: a directory that took a
      // removed directory's inode number finds one too, and its files are not
      // this directory's. When this directory reports the EARLIER birth time
      // it cannot be that later directory, so the store is its own and holds
      // the newer backups: nothing is restored, from the store or from the
      // tree. Otherwise the two cases cannot be told apart, and the archive in
      // the tree is used as before, with the store named beside it. A tree
      // with no archive to use gets "No backup found" from here, naming the
      // store, and so never reaches the two throws below, which say that for
      // a directory with no such store.
      const others = await findOtherBirthStores(targetReal);
      if (others.kind === 'unknown') {
        throw new Error(
          others.dir
            ? `The backup store ${others.dir} could not be used: ${others.reason}, so whether it holds this `
              + 'directory\'s backups is not known. Nothing was restored. Check that directory, then run rollback again.'
            : `The backup store for this directory could not be located: ${others.reason}. Nothing was restored.`,
        );
      }
      otherBirthStores = others.stores;
      const named = (stores: OtherBirthStore[]): string => stores
        .map((s) => `${s.dir}${s.lastKnownPath ? ` (last seen at ${s.lastKnownPath})` : ''}`)
        .join(', ');
      const own = otherBirthStores.filter((s) => s.targetBornEarlier);
      if (own.length > 0) {
        throw new Error(
          'This directory\'s backups are in the backup store under a later creation time than the filesystem '
          + `reports for it now, so rollback did not match them to it and restored nothing: ${named(own)}. `
          + 'A reported creation time moves back when the directory\'s modification time is set earlier, as '
          + 'touch -t, rsync -a, tar -x and cp -p do on macOS. Copy the files back by hand from the run '
          + `directories inside ${own.length === 1 ? 'that store' : 'those stores'}.`,
        );
      }
      if (otherBirthStores.length > 0 && !(await this.inTreeArchiveHoldsRun(targetReal))) {
        throw new Error(
          'No backup found. A backup store with this directory\'s device and inode number, kept under another '
          + `creation time, was not used: ${named(otherBirthStores)}. ${OTHER_BIRTH_STORE_MEANING}`,
        );
      }

      // No run in the store: an archive an earlier version wrote INSIDE the
      // tree is still restorable. Check that it is a real directory in the
      // tree, not a link out of it (#321). `access` follows symlinks, so a
      // `.hackmyagent-backup -> /attacker/drop` passed this gate and rollback
      // then read its manifest and restored from its contents.
      //
      // #334 — only `realpath.native` canonicalizes case; the JS `realpath`
      // returns the caller's spelling for the final component. Everything
      // below is built from whatever this returns, so the two cannot diverge.
      try {
        const joinedBase = path.join(targetReal, BACKUP_DIR_NAME);
        const baseSt = await fs.lstat(joinedBase);
        if (baseSt.isSymbolicLink() || !baseSt.isDirectory()) {
          throw new Error('not a real backup directory');
        }
        backupBaseDir = await fs.realpath(joinedBase);
        if (!this.isPathWithinDirectory(backupBaseDir, targetReal)) {
          throw new Error('backup directory resolves outside the tree');
        }
      } catch {
        throw noBackupFound();
      }
      backupSource = 'in-tree';
    }

    // Find the most recent backup.
    //
    // #334 — DIRECTORIES only. This filtered dotfiles and nothing else, so an
    // ordinary file dropped in the backup base — `zzz` sorts above every stamp —
    // was selected as "the latest backup", and every legitimate rollback in that
    // tree failed on it. `withFileTypes` decides by what the entry IS rather
    // than by what it is called.
    const sortedBackups = (await listArchiveRuns(backupBaseDir)).sort().reverse();

    if (sortedBackups.length === 0) {
      throw noBackupFound();
    }

    // Select a backup that can actually be USED, trying the next candidate when
    // one cannot (#338).
    //
    // The highest-sorting name is a GUESS, and it is a guess at a name the
    // scanned tree can write: a cloned repo shipping
    // `.hackmyagent-backup/9999-99-99-999999/` sorts above every real stamp and
    // is therefore always selected. Treating that guess as final meant one
    // unusable directory disabled the recovery path of a tool that had just
    // rewritten the user's files — permanently, since nothing consumed it and
    // the next run selected it again.
    //
    // Advancing is not a suppression channel: every candidate passed over is
    // reported by name and reason, and NONE is deleted. HMA could not read them,
    // so it cannot know they hold nothing.
    //
    // "Usable" means only that a plausible manifest could be parsed out of it. A
    // candidate that parses is the backup for this run whatever its entries
    // then do — advancing on a RESTORE failure would silently reach past a real
    // backup into an older one and put stale content back, which is #332's harm.
    const skippedBackups: Array<{ name: string; reason: string }> = [];
    /** Candidates that listed files and restored none of them. Kept, never used. */
    const barren: Array<{
      name: string; at: string; dir: string;
      manifest: BackupManifest; unrestored: RollbackReport['unrestored'];
    }> = [];
    let restored: string[] = [];
    let modesRestored: RollbackReport['modesRestored'] = [];
    let unrestored: RollbackReport['unrestored'] = [];
    let backupReal: string | undefined;
    let backupDir: string | undefined;
    let latestBackup: string | undefined;
    let manifest: BackupManifest | undefined;

    for (const candidate of sortedBackups) {
      const candidateDir = path.join(backupBaseDir, candidate);
      // The selected backup gets the same treatment as its parent: the tree
      // chose which entry sorts highest, so it can offer a symlink here too
      // (#318/#321). Resolved once, and everything read out of it is required to
      // resolve back inside this directory.
      //
      // #334 — and it says which of those it was. These refusals used to report
      // "Backup manifest is unreadable", naming a `.manifest.json` that was
      // never opened, so the user was sent to look at the wrong file for a cause
      // that was the directory itself.
      // Every reason below is a FIXED sentence. The candidate's name is already
      // tree-derived and the report escapes it; the reason must not become a
      // second channel for tree bytes, which is what an errno message or a
      // resolved link target would be.
      let candidateReal = '';
      let dirRefusal: string | undefined;
      try {
        const st = await fs.lstat(candidateDir);
        if (st.isSymbolicLink()) dirRefusal = 'it is a symbolic link, and rollback does not read through one';
        else if (!st.isDirectory()) dirRefusal = 'it is not a directory';
        // #1051 — a run this account did not create holds whatever files and
        // modes the account that did chose to list.
        else if (!ownedByCurrentUser(st)) dirRefusal = 'it belongs to another user account, and rollback restores only from a backup this account took';
        else {
          candidateReal = await fs.realpath(candidateDir);
          if (!this.isPathWithinDirectory(candidateReal, backupBaseDir)) {
            dirRefusal = 'it resolves to somewhere outside the backup directory';
          }
        }
      } catch {
        dirRefusal = 'the filesystem would not say what it is';
      }
      if (dirRefusal) {
        skippedBackups.push({ name: candidate, reason: dirRefusal });
        continue;
      }

      // Size-guarded. #305's follow-up bounded the manifest read on the SCAN
      // path and explicitly exempted this one, on the grounds that "rollback
      // only ever reads a manifest HMA itself just wrote". #312 disproved that.
      //
      // Fails closed: an implausible manifest makes the candidate unusable, and
      // refusing to parse one cannot lose a real rollback — `createBackup`
      // writes a list of paths, not payloads.
      let manifestRefusal: string | undefined;
      try {
        const manifestPath = path.join(candidateReal, '.manifest.json');
        const stat = await fs.stat(manifestPath);
        // Per candidate, not cumulative. A shared allowance across the loop was
        // a wedge of exactly the shape this change exists to remove: eleven
        // directories carrying 1MB of invalid JSON each exhausted it before the
        // real backup was reached, and nothing is deleted, so re-running never
        // helped. Dropping it costs reads bounded by bytes the tree has already
        // written to disk — sequential, no amplification — and each candidate is
        // still capped at a size no real manifest reaches.
        if (!stat.isFile()) manifestRefusal = 'its .manifest.json is not a regular file';
        else if (stat.size > MAX_MANIFEST_SIZE) manifestRefusal = 'its .manifest.json is implausibly large';
        if (!manifestRefusal) {
          manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
        }
      } catch {
        // Never the thrown message: a JSON parse error quotes the file, and that
        // file is in the scanned tree. Whatever went wrong, the user's next step
        // is the same, and it does not depend on the parser's phrasing.
        manifestRefusal = 'its .manifest.json could not be read as a backup manifest';
      }
      if (manifestRefusal) {
        skippedBackups.push({ name: candidate, reason: manifestRefusal });
        continue;
      }

      // Try this candidate's restores HERE, because the decision to use it
      // depends on what they do.
      //
      // Refining `backupHoldsCopy` was not enough and could never have been: the
      // scanned tree controls BOTH ends. It plants a real regular file in the
      // forged backup — so the copy genuinely is there — and plants a directory,
      // or a link pointing out of the tree, at the DESTINATION. The restore then
      // fails for a reason that has nothing to do with the copy, retention is
      // correct to keep the directory, and the wedge is back: measured three
      // runs each on `destdir`, `destlink-out` and `destlink-dangling`, nothing
      // restored, the real backup never reached. Any predicate over the tree's
      // own bytes loses this game.
      //
      // So the LOOP is what changes. A candidate that promised entries and
      // delivered none of them is not this run's backup, whatever the reason: it
      // is kept (it may hold bytes nobody can read yet) and REPORTED, and the run
      // moves to the next one. A candidate that restored something, or that
      // promised nothing, is the backup — advancing past either of those is what
      // would reach into an older run and restore stale content.
      const attempt: RollbackReport['unrestored'] = [];
      const put: string[] = [];
      // Recorded modes are honored for a store run only. See `existingFileModes`.
      const modes = backupSource === 'store' ? manifest?.existingFileModes : undefined;
      const modeOnly = backupSource === 'store' ? Object.entries(manifest?.modeOnlyFiles ?? {}) : [];
      for (const file of manifest?.existingFiles ?? []) {
        const restoreMode = modes && Object.prototype.hasOwnProperty.call(modes, file) ? modes[file] : undefined;
        const outcome = await this.restoreOneBackupFile(candidateReal, targetReal, file, restoreMode);
        if (outcome.ok) {
          put.push(file);
        } else {
          const base = RESTORE_REFUSAL_REASONS[outcome.cause];
          attempt.push({
            path: file,
            reason: outcome.detail ? `${base} (${outcome.detail})` : base,
            backupHoldsCopy: outcome.backupHoldsCopy,
          });
        }
      }
      // #1039 — mode-only entries, after the copies. A path with both kinds was
      // merged into `existingFiles` when the copy was taken, so none is set twice.
      // The run holds no copy for any of these, so an entry that does not go
      // back never keeps the run on disk; its reason carries the mode instead.
      const modesPut: RollbackReport['modesRestored'] = [];
      const contentFailures = attempt.length;
      for (const [file, recorded] of modeOnly) {
        const outcome = await this.restoreOneMode(targetReal, file, recorded);
        if (outcome.ok) modesPut.push({ path: file, mode: outcome.mode });
        else attempt.push({ path: file, reason: outcome.reason, backupHoldsCopy: false });
      }
      // A candidate that promises NOTHING contributes nothing either, and the
      // cheapest forgery there is — 49 bytes of empty manifest — used to be
      // selected, restore nothing, print "[+] Rollback complete", consume
      // itself, and say nothing about the backup behind it. Three of them cost
      // a user three runs of reading success before recovery. Advancing past it
      // cannot write anything stale, because it would have written nothing.
      //
      // #1039 — that forgery is a directory INSIDE the tree. A run in the store
      // is one HackMyAgent wrote, and since a run copies only what a fix changed,
      // one that lists nothing is a `--fix` run that changed nothing. It is the
      // newest run, so it is the one this rollback undoes: passing over it would
      // undo the run before it in the same step and leave it on disk for ever,
      // reported as a directory that may not be the user's.
      const promisesNothing = (manifest?.existingFiles.length ?? 0) === 0
        && (manifest?.createdFiles.length ?? 0) === 0
        && (manifest?.legacyCreatedFiles?.length ?? 0) === 0
        && modeOnly.length === 0;
      if (promisesNothing && backupSource === 'in-tree' && sortedBackups.indexOf(candidate) < sortedBackups.length - 1) {
        barren.push({
          name: candidate, at: candidateReal, dir: candidateDir,
          manifest: manifest as BackupManifest, unrestored: [],
        });
        continue;
      }
      // Only a COPY that did not go back makes a candidate barren. A mode-only
      // entry that could not be set (the file deleted since, say) is reported
      // below, but passing over the run for it would put an older run's
      // content back over the user's later work.
      if (put.length === 0 && modesPut.length === 0 && contentFailures > 0) {
        barren.push({
          name: candidate, at: candidateReal, dir: candidateDir,
          manifest: manifest as BackupManifest, unrestored: attempt,
        });
        continue;
      }

      restored = put;
      modesRestored = modesPut;
      unrestored = attempt;
      backupReal = candidateReal;
      backupDir = candidateDir;
      latestBackup = candidate;
      break;
    }

    // Every candidate was barren. There is nothing behind them to be wedged out
    // of, so the newest one becomes this run's backup after all: the user gets
    // the full per-entry report and the retention decision, instead of a
    // one-line refusal that names no reason. The no-wedge property is unaffected
    // — passing over only matters when there IS something behind.
    if (!backupReal && barren.length > 0) {
      const first = barren.shift()!;
      backupReal = first.at;
      backupDir = first.dir;
      latestBackup = first.name;
      manifest = first.manifest;
      restored = [];
      modesRestored = [];
      unrestored = first.unrestored;
    }

    if (!backupReal || !backupDir || !latestBackup || !manifest) {
      const tried = skippedBackups.length;
      throw new Error(
        `None of the ${tried} backup director${tried === 1 ? 'y' : 'ies'} under ${backupBaseDir} `
        + `can be used. ${skippedBackups.map((s) => `${s.name}: ${s.reason}`).join('; ')}. `
        + 'Restore files by hand from whichever of them holds them, then delete it.',
      );
    }

    // How many candidates the tree is holding in front of the ones behind this
    // run's choice. Reported when the rollback does not complete, so a user
    // looking at a retained directory is told there is something behind it.
    const remainingBehind = sortedBackups.length - sortedBackups.indexOf(latestBackup) - 1;

    const report: RollbackReport = {
      restored,
      modesRestored,
      removed: [],
      keptModified: [],
      keptUnverifiable: [],
      unrestored,
      unremoved: [],
      skippedBackups,
      barrenBackups: barren.map((b) => ({ name: b.name, listed: b.unrestored.length })),
      backupsBehind: remainingBehind,
      backupUsed: latestBackup,
      backupSource,
      backupBase: backupBaseDir,
      otherBirthStores: otherBirthStores.length > 0
        ? otherBirthStores.map((s) => ({ dir: s.dir, lastKnownPath: s.lastKnownPath }))
        : undefined,
    };

    // Restore existing files from backup.
    //
    // #312 — the manifest is read from the SCANNED tree, which is attacker-
    // controlled, and this loop had no containment check while the
    // `createdFiles` loop below did. A cloned repo carrying its own
    // `.hackmyagent-backup/9999-99-99-999999/` (which sorts above any real
    // stamp, so it is always selected as the latest) turned `rollback` into an
    // arbitrary file write:
    //
    //   existingFiles: ["../<stamp>/authorized_keys"]
    //   -> copies the attacker's bytes OUTSIDE the scanned tree
    //   -> "[+] Rollback complete / Restored 1 modified file"
    //
    // #318 — and that guard closed only the `..` half. It reasoned that
    // "guarding the destination is sufficient for both ends: if the joined
    // destination stays inside targetDir, the normalized relative path has no
    // leading `..`, so the source cannot climb out of backupDir either" — a
    // statement about path arithmetic, not about the filesystem, and false in
    // both directions. `evil/sshlink -> /home/victim/.ssh` plus
    // `existingFiles: ["sshlink/authorized_keys"]` wrote the attacker's bytes to
    // `/home/victim/.ssh/authorized_keys` and printed
    // `restored sshlink/authorized_keys`; a symlink INSIDE the backup pulled
    // out-of-tree content the other way. Both ends are now resolved, and the
    // `..` case is still refused before any syscall is spent on it.

    // Remove files a fix stage created — but only when the bytes on disk are
    // still the bytes HMA wrote. Any edit since means the file is the user's
    // now, and a rollback of our changes is not a licence to delete it.
    //
    // Resolved, for the same reason as the restore loop: the manifest names both
    // the path AND the hash it must match, so a forged entry pointing through a
    // symlink at a file whose contents the attacker knows is a DELETE primitive
    // aimed outside the tree. #318 named the write; this is the same defect with
    // the arrow reversed.
    for (const created of manifest.createdFiles) {
      // Not followed: a symlink where a generated file should be is not the file
      // HMA generated, and unlinking through it would delete the target instead.
      const resolved = await this.resolveInsideTree(targetReal, created.path, { followLeafLink: false });
      // #342 — this used to be a bare `continue`. HackMyAgent said it would
      // remove the file, could not, and reported "Rollback complete / removed 0
      // generated files" with exit 0 while the file was still on disk. The
      // symlinked-`SOUL.md` fixture the #327 test builds hits it exactly, and
      // that test asserted only that the link's target survived — never that the
      // user is told — which is why the gap survived the change named for it.
      if (!resolved.ok) {
        report.unremoved.push({
          path: created.path,
          reason: RESTORE_REFUSAL_REASONS[resolved.cause],
        });
        continue;
      }
      const filePath = resolved.path;
      let current: Buffer;
      try {
        current = await fs.readFile(filePath);
      } catch (err) {
        // Only ENOENT proves it is already gone. Any other errno proves nothing,
        // and "I could not read it" must not become "there was nothing to
        // revert" — #313's inference, in the one loop that had no channel to
        // report it through.
        if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
          report.unremoved.push({
            path: created.path,
            reason: 'it could not be read, so HackMyAgent cannot tell whether it generated it',
          });
        }
        continue;
      }
      const currentHash = crypto.createHash('sha256').update(current).digest('hex');
      if (currentHash !== created.sha256) {
        report.keptModified.push(created.path);
        continue;
      }
      try {
        await fs.unlink(filePath);
        report.removed.push(created.path);
      } catch {
        report.keptModified.push(created.path);
      }
    }

    // v1 manifests listed every absent backup candidate as "created" with no
    // hash. Deleting on that basis is what could remove a user's own file, so
    // these are reported instead of acted on.
    for (const file of manifest.legacyCreatedFiles ?? []) {
      // #312 — no write here, but an unguarded path still lets a forged
      // manifest probe for files outside the tree and have their existence
      // reported back. #318 — and a lexical guard does not stop that probe,
      // only a `..` in it. All three manifest loops resolve.
      const resolved = await this.resolveInsideTree(targetReal, file, { followLeafLink: false });
      // #342 — same gap, same silence. This loop only ever REPORTS, so a path it
      // cannot resolve produced no line at all and the entry vanished from the
      // report entirely.
      if (!resolved.ok) {
        report.unremoved.push({
          path: file,
          reason: RESTORE_REFUSAL_REASONS[resolved.cause],
        });
        continue;
      }
      try {
        await fs.access(resolved.path);
        report.keptUnverifiable.push(file);
      } catch {
        // Never created — nothing to report.
      }
    }

    // Remove the used backup — but only when it has been fully used.
    //
    // #327 — an entry this run could not restore may have its only remaining
    // copy inside this directory, so deleting it would destroy the bytes the
    // rollback was asked to bring back. Measured on an ordinary symlinked config
    // with no attacker: `[+] Rollback complete`, exit 0, and no copy of the
    // original left anywhere in the tree.
    //
    // #338 — but "may" is not "does", and retaining on the weaker claim turned
    // this fix into a permanent denial of recovery. A directory the tree ships
    // as `9999-99-99-999999/` holding a manifest that names a file it does not
    // contain is selected every run, restores nothing, and was then KEPT — so
    // the next run selected it again, and the real backup behind it was never
    // reachable. Before this fix a failing selection consumed itself and the
    // second run recovered; after it, three runs recovered nothing.
    //
    // So retention is decided on the fact rather than on the possibility: keep
    // the directory when it still holds a copy of something that did not go
    // back. A backup that restored nothing and holds nothing is protecting
    // nothing, and deleting it is what lets the run behind it be reached.
    //
    // "Holds nothing" is PROVEN per entry (see `restoreOneBackupFile`): a
    // lexical escape or an ENOENT. Anything the filesystem would not answer
    // counts as holding a copy, because the cost of being wrong in that
    // direction is the user's last bytes.
    const retaining = report.unrestored.some((u) => u.backupHoldsCopy);
    if (retaining) {
      report.backupRetainedAt = backupReal;
    } else {
      // GUARDED, and this is the whole of the fix.
      //
      // `force: true` ignores one thing — the path not existing. Everything
      // else throws, and it throws HERE, after every file has been restored and
      // the entire report assembled. A `0500` subdirectory inside a forged
      // backup is enough: `fs.rm` cannot unlink through a directory it may not
      // write, and the exception replaced the whole report — restored list,
      // unrestored list, `backup kept at`, "copy those files back by hand" —
      // with a bare EACCES. That is #344's harm reached through a different
      // door, and the barren-candidate change fires this `rm` in more cases
      // than before, so the door is wider than it was.
      //
      // The removal is housekeeping. The rollback already happened, and a
      // failure to tidy up must not throw away the account of it.
      try {
        await fs.rm(backupReal, { recursive: true, force: true });
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        report.backupRemovalFailed = {
          path: backupReal,
          reason: code
            ? `${code} — the directory or something inside it could not be removed`
            : 'it could not be removed',
        };
      }
    }

    return report;
  }
}
