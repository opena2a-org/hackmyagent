---
type: changed
issue: 1043,376
---
- `secure --help` says where `--fix` keeps its pre-fix copies and that
  `hackmyagent rollback` restores them; `rollback`'s "No backup found" error
  names the backup store root it searched and the variable that chose it, and
  no longer tells you to run `--fix` first.
