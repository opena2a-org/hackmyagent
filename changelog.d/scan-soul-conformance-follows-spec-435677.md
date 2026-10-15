---
type: fixed
---
#### scan-soul reports the conformance level the governance specification defines ([opena2a-standards/agent-governance-spec#41](https://github.com/opena2a-standards/agent-governance-spec/issues/41))

- `scan-soul` set Standard and Hardened from the score alone once every
  critical control passed, so a governance file with a failing HIGH control
  could read Hardened. Conformance now follows the specification, over the
  controls that apply to the file's tier and profile: Standard needs every
  applicable HIGH control to pass and a score of 60 or more, and Hardened
  needs every applicable control to pass and a score of 75 or more. A file
  with a failing HIGH control reads Essential, and a file with any failing
  control reads at most Standard. The `conformance` field of `--json` output
  carries the same level.
- The score, the maturity `level` and the exit codes are unchanged. A level
  recorded by an earlier version, such as a badge or a published scan, is
  not recomputed.
