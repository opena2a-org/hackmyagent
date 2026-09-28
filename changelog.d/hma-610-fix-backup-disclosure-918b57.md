---
type: fixed
issue: 610
---
#### Every `--fix` run that wrote a backup says where it is (#610)

- `secure --fix` prints `Backup created:` whenever it wrote a backup, including
  a run that attempted no fix; before, a second run on a hardened tree added a
  run directory under `.hackmyagent-backup/` and said nothing.
- `secure-openclaw --fix` prints the backup and rollback lines on the NOT
  MEASURED path too: the scanner can write a `.gitignore` and the backup before
  the OpenClaw filter finds nothing to evaluate.
- `secure-openclaw --fix --json` carries `backupPath`, as `secure --format json`
  does.
