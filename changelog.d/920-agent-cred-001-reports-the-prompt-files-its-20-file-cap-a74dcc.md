---
type: fixed
issue: 920
---
#### AGENT-CRED-001 reports the prompt files its 20-file cap leaves unread (#920)

- AGENT-CRED-001 reads at most 20 system-prompt files. On a tree with more,
  the files past the cap were never read, and `secure --json` still showed
  `coverage.truncations: []`, so the credentials category read as fully
  examined. The cap now records a truncation that names how many prompt
  files were not read, and the credentials category prints as partial.
