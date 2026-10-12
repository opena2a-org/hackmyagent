---
type: changed
issue: 1039
---
#### `secure --fix` and `harden-soul` copy a file into the backup only when a fix changes it (#1039)

- 0.33.2 copied every file a fix might change before any fix ran, so the
  backup of a run held a plaintext `.env` even when no fix touched it. Now a
  file is copied just before a fix writes it, and a file no fix writes is not
  in the backup.
- The permissions fix (PERM-001) records the mode a file had before it
  narrows it to 0600, and copies none of its content. `rollback` sets that
  mode back and prints a `mode` line for the file; its summary counts these
  files apart from the restored ones. A recorded mode never restores a
  set-user-id, set-group-id or sticky bit.
- A `--fix` run that changed no file still leaves a backup that lists
  nothing. `rollback` uses that backup, says there was nothing to undo, and
  names the command that undoes the run before it.
- Library: `HardeningScanner.rollback()` returns `modesRestored`, the files
  whose mode it set back.
