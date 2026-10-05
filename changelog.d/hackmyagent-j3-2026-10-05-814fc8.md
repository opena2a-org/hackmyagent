---
type: fixed
issue: 460
---
#### `secure-openclaw` and `secure-nemoclaw`: an `.hmaignore` check rule no longer lowers the risk level or the exit code (#460)

- A `!CHECK-ID` rule in `.hmaignore` removed the matching findings from the
  report and from the verdict, so suppressing the critical and high checks on
  `test-fixtures/insecure-openclaw` moved `secure-openclaw` from
  `Risk Level: Critical`, exit 1 to `Risk Level: Moderate`, exit 0, and neither
  command mentioned the suppression. `secure` on the same tree reported
  exit 1.
- Both commands now handle suppressions the way `secure` and `check` do. A
  suppressed finding leaves the list but still counts toward the risk level
  and the exit code. A `Suppressed:` line names every suppressed check and
  what it would have reported, and a `Scope:` line counts the findings an
  `.hmaignore` path rule excluded. `--json` carries the same `suppressed` and
  `outOfScope` records as `secure --json`.
