---
type: fixed
issue: 1051
---
#### `secure --fix` and `rollback` refuse a backup store another user account created (#1051)

- A backup store is named after the project directory's device, inode number
  and birth time, which any account can read. Before, with `HMA_BACKUP_HOME`
  set to a directory other accounts can write, another account could create a
  project's store first, with a run listing files and modes, and `rollback`
  restored those files into the project. Now a store directory or `target.json`
  this account does not own is refused, and `--fix` detects only with
  `FIX-BACKUP-FAILED` naming it; `rollback` refuses it and passes over a run
  directory another account created, naming it in the report.
- A store root that is group- or world-writable without the sticky bit is
  refused the same way, and the fix line names `chmod go-w` on it or another
  `HMA_BACKUP_HOME`. A shared root with the sticky bit, as `/tmp` has, is
  still accepted.
