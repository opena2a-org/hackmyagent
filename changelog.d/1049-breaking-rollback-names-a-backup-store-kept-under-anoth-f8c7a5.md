---
type: fixed
issue: 1049
breaking: true
---
#### Breaking: `rollback` names a backup store kept under another creation time and no longer reports that the directory has no backup (#1049)

- The backup store finds a directory by its device number, inode number and
  creation time. The creation time a filesystem reports can change after
  `secure --fix`: on macOS it moves back when the directory's modification
  time is set earlier, as `touch -t`, `rsync -a`, `tar -x` and `cp -p` do.
  `hackmyagent rollback` then found no backup for the directory. With an older
  `.hackmyagent-backup` directory in the tree it restored that one, exited 0
  with "Rollback complete", and reported "the backup store held none for it"
  while the store held the newer backup. With none in the tree it exited 1
  with "No backup found".
- `rollback` now looks for stores kept under the directory's device and inode
  number and another creation time, names each with the path it was last used
  for, and never restores from one. When the directory reports an earlier
  creation time than such a store, the store is that directory's: `rollback`
  exits 1, restores nothing from the store or from the tree, and says to copy
  the files back by hand from the run directories inside the store. That is
  the exit code change: the same run exited 0 before.
- When the directory reports a later creation time, a changed creation time
  cannot be told from a new directory that took a removed directory's inode
  number. `rollback` then behaves as before, restoring from a
  `.hackmyagent-backup` directory in the tree or exiting 1 with "No backup
  found", and in both cases names the store it did not use. Its report no
  longer says the store held no backup when it names one, and the "No backup
  found" message that names a store does not say to run `secure --fix` first:
  that run would back up the files as the earlier `--fix` left them.
- When the store's root directory cannot be listed, `rollback` cannot tell
  whether such a store exists. It exits 1, names that directory and restores
  nothing, where it restored from the tree or reported "No backup found"
  before.
- Not changed: `secure` prints no `Backups:` line for a store kept under
  another creation time, and the next `secure --fix` starts a new store for
  the directory.
