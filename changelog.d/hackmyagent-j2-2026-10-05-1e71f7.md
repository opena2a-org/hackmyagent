---
type: fixed
issue: 861
---
#### `harden-soul --profile <unknown>` no longer creates a backup directory before refusing (#861)

- **`harden-soul --profile <value>` with a value that is not a profile now leaves the target
  directory as it was.** It already exited 1 and named the accepted profiles, but it checked the
  value only after taking its backup, so every refused run left a new
  `.hackmyagent-backup/<run>/` holding a manifest and a copy of the governance file. The value is
  now checked before the backup is taken. Accepted profiles and `--dry-run` are unchanged.
