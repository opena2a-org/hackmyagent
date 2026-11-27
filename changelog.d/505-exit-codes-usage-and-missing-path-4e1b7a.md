---
type: changed
issue: 505
breaking: true
---
#### A usage error exits 64, and `scan-soul` and `fix-all` on a missing directory exit 2 (#505)
- Before, a command line the CLI could not parse (an unknown command or
  option, a missing or extra operand, an option without its value) exited 1,
  the code a scan uses for a critical or high finding. A bare or empty
  `explain` did the same. A CI job could not tell a typo from a finding.
- Now each of them exits 64 (`EX_USAGE`) with the same message as before.
  `explain` with an unknown check ID still exits 1.
- Before, `scan-soul <dir>` and `fix-all <dir>` (with or without `--dry-run`,
  `--scan-only` or `--json`) exited 1 when the directory did not exist, while
  `secure`, `check`, `scan-text` and `detect` exited 2. Now both exit 2, not
  measured, like the others.
- A CI job that read exit 1 from these runs now gets 64 or 2. Both are still
  non-zero, so a job that only checks for a failure is unchanged.
