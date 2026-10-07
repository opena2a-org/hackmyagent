---
type: fixed
issue: 395
---
#### The advertised check count no longer includes three checks that could never run (#395)

- `CODEINJ-001`, `TMPPATH-001` and `ENVLEAK-001` were counted in the static
  suite `secure` reports, but nothing called them. They overlap NEMO-005,
  NEMO-006 and NEMO-007, which run at the standard and deep scan depths.
  The three are removed. The suite is now 317 static checks
  across 71 categories (362 checks across 86 categories including the
  NanoMind semantic layer), down from 320 and 74 (365 and 89). The `Checks`
  line no longer prints `3 unreachable`, and `secure --json` reports
  `coverage.unreachableCheckPrefixes` as `[]`. Findings, severities and
  scores do not change.
- NEMO-005, NEMO-006 and NEMO-007 do not report every form the removed
  checks matched. They do not report an `exec()` template literal in which
  no interpolated expression contains `name`, `id`, `input`, `arg`,
  `param`, `flag` or `option`, such as ``exec(`ls -la ${dir}`)``; a `/tmp/`
  path on a line of a `.sh` script that has no `>` and does not write the
  path with `-o` or `install`, such as `cp build.tar /tmp/out.tar`; or
  `env: process.env` passed to a child process without a spread. None of
  these was reported before this change either.
- `mark-stub <id> integrated --check-id` with an ID from one of the removed
  families is now refused as `check-absent` instead of `check-unreachable`.
