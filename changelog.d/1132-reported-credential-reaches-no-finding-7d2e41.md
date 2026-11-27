---
type: fixed
issue: 1132
---
#### A value secure reports as a hardcoded secret no longer appears in another finding (#1132)

- A skill whose credential-request clause ended in a 40-or-more-character
  secret with no vendor prefix got an AST-CRED-003 finding that masked the
  secret and an AST-CRED-001 finding that quoted it whole in its message and
  evidence, marked `redactionStatus: "clean"`. Every finding of the scan now
  has each value reported as AST-CRED-003 replaced with `[REDACTED_SECRET]`
  (or the marker of its vendor shape), and is marked `"applied"` with that
  shape. Values the scan did not report, such as git SHAs and content
  hashes, are left as they are.
- The AST-CRED-003 finding itself is marked `"applied"` rather than
  `"clean"`, since its text was written with the secret removed.
