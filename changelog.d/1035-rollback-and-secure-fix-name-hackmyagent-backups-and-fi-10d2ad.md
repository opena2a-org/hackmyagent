---
type: added
issue: 1035
---
#### `rollback` and `secure --fix` name `hackmyagent backups`, and `--fix` says when it sets a backup store aside (#1035)

- When a backup store was under the scanned directory's key but recorded for
  another directory, `secure --fix` moved it to `<key>.replaced-<time>-<random>`
  and printed nothing about it, so a store that can hold another directory's
  pre-fix copies, credentials among them, was renamed without a word. `--fix`
  now prints one `Backup store set aside:` line with the path it was moved to,
  and that `hackmyagent backups` lists it.
- `rollback --help`, and the `rollback` errors that report no backup found or
  a store it will not restore from, name `hackmyagent backups`, which lists
  every backup store and the directory each was last used for.
- The README shows `hackmyagent backups` beside `rollback`.
- The `Backups:` line of a `secure` text report and every `--json` output are
  unchanged.
