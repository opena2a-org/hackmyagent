---
type: fixed
issue: 445
breaking: true
---
#### `scan --json` exits 1 on a critical or high finding, as `scan` does (#445)

- **The JSON channel of `scan` exited 0 while its body listed criticals.** `scan --help`
  documents "Exit code 1 if critical/high issues found"; the text channel honoured it, and
  the `--json` branch wrote its body and returned before the check, so a CI job piping the
  JSON never failed. Measured against a local server answering 200 on every path: `scan`
  exit 1, `scan --json` exit 0. Both channels now exit 1 on the same run.
