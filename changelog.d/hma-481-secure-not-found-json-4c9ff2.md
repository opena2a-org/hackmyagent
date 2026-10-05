---
type: fixed
issue: 481
breaking: true
---
#### `secure` on a missing target exits 2 and writes JSON under `--json` (#481)

- **A target that does not exist is not measured, and `secure` now says so the way `check`
  does.** `secure --json /no/such/dir` wrote nothing to stdout (the error line went to stderr,
  so a CI step's `JSON.parse` on the report file threw) and exited 1, which the help defines as
  "measured, and a critical/high issue was found". `check` on the same path already exited 2
  with `coverage.measured: false`. Measured on main before this change: `secure --json
  /tmp/no-such-dir-xyz` printed an empty stdout and exited 1; `check /tmp/no-such-dir-xyz`
  exited 2. Now `secure` exits 2 on every channel. Under `--json` (or `--format json`) it writes
  `{hackmyagentVersion, target, verdict: null, exitCode: 2, measured: false, coverage}`, where
  `coverage` is the same block `check` emits (`reason: "target-not-found"`); text mode prints
  `NOT MEASURED — <path> does not exist, so nothing was scanned.` and a `Verify: ls -ld <path>`
  line. The ending stays a registered pre-work refusal (`S002`) and still emits no telemetry
  event; #525 converts the refusal exits once the event carries a reason. `secure --help` lists
  a missing target under exit 2. Regression:
  `__tests__/cli/secure-not-found-unmeasured.test.ts` (JSON document, `--format json`, text
  banner, `secure` and `check` agree) and a cell in `__tests__/cli/exit-event-emission.test.ts`
  (exit 2, no event).
