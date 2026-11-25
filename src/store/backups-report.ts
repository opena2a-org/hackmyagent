/**
 * The text `hackmyagent backups` prints, and the exit code it settles (#1035).
 *
 * A header naming the store root `rollback` searches, one block per store
 * with its state and the command that deletes it, and a footer counting the
 * states. The command reads and never writes, so every delete command is one
 * for the user to run, and only for a directory this account owns.
 *
 * Exit codes:
 *   0  every store is in use by the directory at the path it was last used for,
 *      or there is no store
 *   1  at least one store is not in use: `rollback` run in the directory at its
 *      recorded path would not restore from it, or it records no such path
 *   2  something could not be read: the root, or a store
 *
 * Every path is display-escaped where its line is built, and a delete command
 * is offered only for a path that can be shown and named truthfully
 * (`commandNaming`). A recorded path came from a scanned tree's name, so its
 * bytes are the scanned tree's.
 */
import type { BackupStoreEntry, BackupStoreListing } from './archive-store';
import { escapeForDisplay, escapePathForDisplay } from '../ui/display-safe';
import { commandNaming } from '../ui/shell-quote';

export interface BackupsReport {
  lines: string[];
  exitCode: 0 | 1 | 2;
}

export interface BackupsReportOptions {
  /** How the store root was chosen, as `backupStoreRootSource()` says it. */
  rootSource: string;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The state line of one store, after `state:`. */
function stateLine(entry: BackupStoreEntry, sharedRoot: boolean): string {
  const at = entry.lastKnownPath ? escapePathForDisplay(entry.lastKnownPath) : '';
  const reason = escapeForDisplay(entry.reason ?? '');
  switch (entry.state) {
    case 'in-use':
      return sharedRoot
        ? `not used: rollback run in ${at} refuses it, because other user accounts can write the store root`
        : `in use: rollback run in ${at} restores from it, and has nothing to restore once it is deleted`;
    case 'other-birth':
      return entry.targetBornEarlier
        ? `not used: the directory at ${at} has this store's device and inode number and an earlier creation time, `
          + 'so this store is that directory\'s, kept under the creation time it had at its last --fix. '
          + 'rollback does not restore from it; copy the files back by hand from the run directories inside it.'
        : `not used: the directory at ${at} has this store's device and inode number and another creation time. `
          + 'The store is that directory\'s if the creation time the filesystem reports for it changed after its '
          + 'last --fix, and another directory\'s if this one took a removed directory\'s inode number.';
    case 'other-directory':
      return `not used: another directory is at ${at}, where this store's directory was at its last --fix. `
        + 'If that directory was moved, rollback run in it still restores from this store.';
    case 'directory-gone':
      return `not used: nothing is at ${at}, where this store's directory was at its last --fix. `
        + 'If that directory was moved, rollback run in it still restores from this store; if it was deleted, nothing will.';
    case 'no-path':
      return 'not used by a known directory: its target.json names no path';
    case 'no-record':
      return 'no target.json, so it does not say which directory it is for. rollback restores from it only in the '
        + 'directory whose device, inode number and creation time its name carries.';
    case 'invalid-record':
      return `not used: ${reason}, so rollback refuses it`
        + (at ? `. It names ${at}.` : '');
    case 'not-owned':
      return `not used: ${reason}, so rollback refuses it`;
    case 'not-a-directory':
      return 'not a store: a symbolic link or a file stands at a store\'s name, and rollback refuses it';
    case 'replaced':
      return 'not used: a later --fix moved it aside, because its target.json was not a record HackMyAgent wrote '
        + 'or named a directory created at another time'
        + (at ? `. It was last used for ${at}.` : '');
    case 'unknown':
      return `could not be read: ${reason}`;
  }
}

/** Whether a store counts as in use, as the footer and the exit code count it. */
function inUse(entry: BackupStoreEntry, sharedRoot: boolean): boolean {
  return entry.state === 'in-use' && !sharedRoot;
}

/** The block for one store: its path, its state, its run count and how to delete it. */
function storeBlock(entry: BackupStoreEntry, sharedRoot: boolean): string[] {
  const lines = [escapePathForDisplay(entry.dir)];
  lines.push(`  state:    ${stateLine(entry, sharedRoot)}`);
  if (entry.runs !== undefined) {
    lines.push(`  backups:  ${entry.runs === 0 ? 'none' : plural(entry.runs, '--fix run', '--fix runs')}`);
  }
  if (!entry.deletable) {
    lines.push(
      entry.state === 'not-owned'
        ? '  delete:   it belongs to another user account, so no command to delete it is offered'
        : '  delete:   review it and remove it by hand if it is not yours',
    );
    return lines;
  }
  const remove = commandNaming(entry.dir, (cited) => `rm -rf ${cited}`);
  lines.push(
    remove
      ? `  delete:   ${remove}`
      : '  delete:   remove that directory by hand (the name above is an escaped rendering, so a command built '
        + 'from it could name a different directory)',
  );
  return lines;
}

/** The report for a listing, and the exit code it settles. */
export function renderBackupsReport(listing: BackupStoreListing, opts: BackupsReportOptions): BackupsReport {
  const source = escapeForDisplay(opts.rootSource);
  if (listing.kind === 'unknown') {
    const where = listing.root ? `the backup store root ${escapePathForDisplay(listing.root)} (${source})` : `the backup store root (${source})`;
    return {
      lines: [
        `Could not list ${where}: ${escapeForDisplay(listing.reason)}.`,
        'Nothing was written or deleted.',
      ],
      exitCode: 2,
    };
  }
  if (listing.kind === 'no-root') {
    return {
      lines: [
        `No backup store root at ${escapePathForDisplay(listing.root)} (${source}), so no --fix run kept a backup there.`,
        'Nothing was written or deleted.',
      ],
      exitCode: 0,
    };
  }

  const shared = listing.sharedRoot !== undefined;
  const lines = [`Backup stores under ${escapePathForDisplay(listing.root)} (${source}):`];
  if (listing.sharedRoot) {
    lines.push(`  ${escapeForDisplay(listing.sharedRoot)}. rollback refuses every store under it.`);
  }
  for (const entry of listing.stores) {
    lines.push('', ...storeBlock(entry, shared));
  }

  const used = listing.stores.filter((e) => inUse(e, shared)).length;
  const unread = listing.stores.filter((e) => e.state === 'unknown').length;
  const unused = listing.stores.length - used - unread;
  lines.push('');
  lines.push(
    listing.stores.length === 0
      ? 'No backup stores.'
      : `${plural(listing.stores.length, 'backup store', 'backup stores')}: ${used} in use, ${unused} not in use`
        + (unread > 0 ? `, ${unread} could not be read.` : '.'),
  );
  if (listing.otherEntries > 0) {
    lines.push(
      `${plural(listing.otherEntries, 'other entry', 'other entries')} under the root `
      + `${listing.otherEntries === 1 ? 'is not a backup store and is' : 'are not backup stores and are'} not listed.`,
    );
  }
  lines.push('Nothing was written or deleted.');

  const exitCode: 0 | 1 | 2 = unread > 0 ? 2 : unused > 0 ? 1 : 0;
  return { lines, exitCode };
}
