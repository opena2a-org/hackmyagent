---
type: added
issue: 1035
---
#### `backups` lists every backup store `secure --fix` kept, and changes nothing (#1035)

- `secure` named only the backup store of the directory it scanned. A store
  whose directory was moved, deleted or given another creation time stayed
  outside the project, holding the pre-fix copies, which can include a
  credential a fix removed, and no command named it.
- `hackmyagent backups` lists every store under the root `rollback`
  searches (`$HMA_BACKUP_HOME`, else `$OPENA2A_HOME/backups`, else
  `~/.opena2a/backups`), with the path of the directory each was last used
  for, how many `--fix` runs it holds, and whether `rollback` in that
  directory restores from it: the directory there must have the device,
  inode number and creation time the store is named by. Each store this
  account owns is printed with the `rm -rf` command that deletes it. The
  command creates, writes and deletes nothing.
- It exits 0 when every store is in use or there is none, 1 when at least
  one store is not in use, and 2 when the store root or a store could not be
  read. It takes no arguments or options, and exits 2 when given any.
