---
type: changed
issue: 376
breaking: true
---
#### Breaking: `secure --fix` keeps its pre-fix copies outside the scanned tree; `--json` no longer carries `scoreExcludingOwnArchive` or `inOwnArchive` (#376)

- `secure --fix` keeps its pre-fix copies under `~/.opena2a/backups`, not
  inside the scanned tree. A later scan no longer reports those copies, so the
  score after `--fix` is the live tree's score (measured 35 to 59 on the #298
  fixture). Archives that earlier versions wrote into a tree are still scanned
  and reported until you delete them, and `rollback` still restores from them.
- The backup store is `$HMA_BACKUP_HOME` when that is set, else
  `$OPENA2A_HOME/backups`, else `~/.opena2a/backups`. Each directory you fix
  has its own directory in the store, found by the directory's identity on the
  filesystem and not by its path. `rollback` therefore finds the backups of a
  directory that was moved or renamed, or that is reached through a symbolic
  link, and two directories with the same name do not share one. The store's
  directories are created with mode 0700 and the copies with mode 0600. A
  directory that already exists at `$HMA_BACKUP_HOME` keeps the mode it has.
- `--fix` applies no fix when it cannot take a backup, and reports
  `FIX-BACKUP-FAILED` with the cause and the remedy. The causes are a store
  that cannot be created (a read-only home directory), a store that would sit
  inside the directory being fixed (`secure --fix ~`), and a relative path in
  `HMA_BACKUP_HOME` or `OPENA2A_HOME`. With a relative path `rollback` exits
  non-zero and names the variable.
- `--fix` prints the absolute path of the backup it wrote and says that it
  holds a copy of every file the run backed up, whether or not a fix changed
  it, that it can therefore hold a credential still in use, and that it stays
  after the directory is deleted. Every `secure` text report for that
  directory, the `--fix` run itself and `-b oasb-1` and `-b oasb-2` included,
  prints one `Backups:` line with the number of backups, the path
  and the `rm -rf` command that deletes them. The line is not a finding and
  does not change the score.
- `rollback` restores from the store. It restores from a `.hackmyagent-backup`
  directory inside the tree only when the store holds no backup for the
  directory, and its report names that source. After the store is deleted,
  `rollback` exits 1 with "No backup found" unless such a directory is in the
  tree.
- `--json`: the top-level `scoreExcludingOwnArchive` field and the
  `inOwnArchive` field on each finding are removed. No run reports a copy in a
  backup of its own any more, so there is no second score to carry.
  `backupPath` is kept and is now an absolute path outside the scanned
  directory. `inArchive` is kept and marks a finding inside a
  `.hackmyagent-backup` directory that an earlier version left in the tree.
  The text report no longer prints the `Live tree:` line.
- Library: the `SecurityFinding` type no longer has `inOwnArchive`, and the
  result of `HardeningScanner.scan()` no longer has `scoreExcludingOwnArchive`.
