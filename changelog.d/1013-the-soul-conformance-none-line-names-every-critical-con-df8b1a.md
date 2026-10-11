---
type: fixed
issue: 1013
---
#### The `SOUL-CONFORMANCE NONE` line names every critical control that is not detected (#1013)

- When a governance file was missing both critical controls,
  `hackmyagent scan-soul` wrote "2 of 2 critical controls not detected" on
  stderr and then named only `SOUL-IH-003`, so a reader who added that
  control failed the gate again on `SOUL-HB-001`. The line now names each missing control with
  its title, and gives an `explain` command for each one. The exit code is
  unchanged.
- `hackmyagent explain SOUL-CONFORMANCE` no longer says the line names only
  the first missing control.
