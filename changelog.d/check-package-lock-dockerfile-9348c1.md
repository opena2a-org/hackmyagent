---
type: fixed
---
#### `check <package>` no longer reports a missing lock file or Dockerfile on a downloaded package

- Since 0.33.0, `check` on every npm package failed DEP-001 (no dependency lock file) and SANDBOX-001 (no Dockerfile), and both took points off its score: `npm publish` never ships a lock file, and a Dockerfile describes where the consumer deploys, not the package they install. `check` on a downloaded package (npm, PyPI, a cloned repository, an archive URL) now leaves both checks out of its findings, its score and what it shares, alongside the local-only categories it already left out. `secure` and `check` on a local project tree still report both.
