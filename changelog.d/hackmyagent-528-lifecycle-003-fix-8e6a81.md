---
type: fixed
issue: 528
---
#### LIFECYCLE-003 says which file to trim, to what size, and how to check it (#528)

- **The `Context window displacement` fix names the file, its size and share, the size at which
  the check stops firing, the largest server or tool entry when the file is JSON, and a
  `Verify:` command.** It was one sentence of general advice ("Limit component sizes... Implement
  attention anchoring") on a HIGH finding, less actionable than the LOW `SEM-MCP-006` on the same
  `mcp.json`. The stated size comes from the check's own rule (over 60% of the assembled prompt
  once the prompt is over 2,000 characters). Tests rewrite the file at that size and at one
  character more to pin it as the exact boundary. The file name is cited escaped, so an escape
  sequence or a newline in a memory file's name does not reach the text, SARIF help or asp
  remediation as is. Severity, verdict and score are unchanged.
