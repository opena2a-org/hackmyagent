---
type: fixed
issue: 389
---
#### The `.gitignore` that `secure --fix` generates now excludes `.hackmyagent-backup/` (#389)

- When a tree had no `.gitignore`, `secure --fix` wrote one that covered
  `.env`, `*.pem` and `*.key` but not `.hackmyagent-backup/`, the directory the
  same run had just written its pre-fix copies into. A credential the run
  redacted from a live file such as `config.json` stayed in plaintext in the
  backup copy, and `git add -A` after the fix committed it. The generated
  `.gitignore` now lists `.hackmyagent-backup/`, so git ignores the backup
  copies. `hackmyagent rollback` still restores from them.
- An existing `.gitignore` is not changed by this: add `.hackmyagent-backup/`
  to it yourself, or delete the backup once you have rotated the credential.
