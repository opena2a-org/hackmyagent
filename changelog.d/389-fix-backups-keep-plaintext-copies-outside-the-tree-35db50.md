---
type: known-issue
issue: 389
---
- `secure --fix` keeps a plaintext copy of each file a fix changes, as it was
  before the fix, one set per run, in the backup store (`$HMA_BACKUP_HOME`,
  else `$OPENA2A_HOME/backups`, else `~/.opena2a/backups`). A credential a fix
  removed from such a file stays readable there until you delete the backup or
  `hackmyagent rollback` restores from it. A file whose only change is its
  mode, such as a `.env` the permissions fix narrows, is not copied. Deleting
  or re-creating the project does not delete its backups, and no command lists
  the backups of a project that no longer exists; deleting the store root
  removes every project's backups. Revoke a credential a fix removed at the
  service that issued it; deleting the copy is not a substitute. In 0.33.2 the
  copies sat inside the project; this release moves them out of it
  ([#389](https://github.com/opena2a-org/hackmyagent/issues/389),
  [#376](https://github.com/opena2a-org/hackmyagent/issues/376)).
