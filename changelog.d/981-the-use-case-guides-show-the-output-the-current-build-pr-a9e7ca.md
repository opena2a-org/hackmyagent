---
type: fixed
issue: 981
---
#### The use-case guides show the output the current build prints (#981)

- The `secure` samples in `docs/use-cases/red-team-mcp.md`,
  `openclaw-security.md` and `scan-my-agent.md` say they were captured from
  this repository's `test-fixtures`, but no longer matched the build. The
  `insecure-mcp` sample read `7 critical issues found` and `15/100` where
  `secure` prints `6 critical issues found` and `17/100`. The
  `insecure-openclaw` dry run read `12 issues auto-fixable` where it prints 8.
  The samples are now regenerated from the build with
  `node scripts/use-case-samples.mjs --write`. A test fails when a sample
  differs from the build in any line other than the version.
