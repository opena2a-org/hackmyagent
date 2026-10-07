---
type: fixed
issue: 885
---
#### `secure` quick-depth and benchmark `--fix` output name what they ran and wrote (#885)

- `secure --scan-depth quick` cited `secure <dir>` for the standard-depth
  score, which is `command not found` when pasted. It now cites
  `hackmyagent secure <dir>`, or the parent CLI's prefix when
  `HMA_CLI_PREFIX` is set.
- With `--static-only`, the quick-depth score line now says
  `semantic layer off` beside the check-group ratio. Before, it read the same
  as a run with the semantic layer, and only the Checks line told them apart.
- `secure -b oasb-1 --fix` and `secure -b oasb-2 --fix` with `--format json`
  now carry `backupPath`, the key `secure --fix --format json` uses. With
  `-b oasb-1 --format sarif`, `html` or `asp`, the `Backup created:` and
  rollback lines are printed on stderr. Before, these runs wrote
  `.hackmyagent-backup/<run>/` and named it nowhere.
