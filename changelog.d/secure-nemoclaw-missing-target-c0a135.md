---
type: fixed
breaking: true
---
#### `secure-nemoclaw` reports a directory that does not exist as not measured (#1114)

- `secure-nemoclaw <dir>` on a directory that does not exist printed a
  `Risk Level:` and a `Checks:` count for it and exited 0. Now it scans
  nothing and exits 2, with `NOT MEASURED — <dir> does not exist, so nothing
  was scanned.` and `Verify: ls -ld <dir>` on stderr. With `--json` it writes
  the document `secure --json` writes for a missing target: `verdict: null`,
  `exitCode: 2`, `measured: false` and `coverage.reason: "target-not-found"`,
  with no `riskLevel`, `totalChecks` or `issues`. A path that is a file, or a
  directory that cannot be read, ends the same way with `is not a directory`
  or `could not be read` in place of `does not exist`.
- This changes an exit code: `secure-nemoclaw` on such a path exited 0 and
  now exits 2.
