---
type: fixed
issue: 491
---
#### A nested artifact's `Verify:` line runs from the directory you scanned from (#491)

- **The terminal report re-bases a nested directory in a `Verify:` citation onto the scan
  target.** Fix text ends with `Verify: hackmyagent secure <dir>`, where `<dir>` is the
  artifact's directory relative to the scan target. A top-level artifact's `.` was already
  replaced with the target; a nested one was printed as is. Measured on main, running
  `secure ../proj` on a tree with `app/SOUL.md`: `Verify: hackmyagent secure app`, which from
  that directory fails with `Directory '<cwd>/app' does not exist`. It now prints
  `Verify: hackmyagent secure ../proj/app`, which runs. Only a proven case is rewritten: a verb
  that takes a directory (never `check` or `scan`), one plain relative operand that does not
  resolve from the working directory and does resolve under the target. `--json`, SARIF and HTML
  fix text is unchanged and still carries no absolute path.
