---
type: fixed
issue: 395
---
#### The advertised check count no longer includes three checks that could never run (#395)

- `CODEINJ-001`, `TMPPATH-001` and `ENVLEAK-001` were counted in the static
  suite `secure` reports, but nothing called them: they duplicate NEMO-005,
  NEMO-006 and NEMO-007, which run on every scan and report the same
  patterns. The three are removed. The suite is now 317 static checks
  across 71 categories (362 checks across 86 categories including the
  NanoMind semantic layer), down from 320 and 74 (365 and 89). The `Checks`
  line no longer prints `3 unreachable`, and `secure --json` reports
  `coverage.unreachableCheckPrefixes` as `[]`. Findings, severities and
  scores do not change.
- `mark-stub <id> integrated --check-id` with an ID from one of the removed
  families is now refused as `check-absent` instead of `check-unreachable`.
