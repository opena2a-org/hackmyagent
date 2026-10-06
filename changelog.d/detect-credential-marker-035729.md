---
type: changed
---
#### `detect` names a credential in an AI config with a labelled marker instead of a prefix and length

- A credential finding in an AI config file (`CLAUDE.md`, `.cursorrules`,
  `.claude/settings.json` and the others `detect` reads) showed the value as
  its vendor prefix, an ellipsis and its length, such as
  `"ANTHROPIC_API_KEY" = sk-ant-api0… (45 chars)`, or `… (30 chars)` for a
  value with no recognised prefix. It now shows the labelled marker, such as
  `"ANTHROPIC_API_KEY" = Anthropic API key: [REDACTED]`, or
  `Credential: [REDACTED]` for a value with no recognised prefix.
- The change applies to the terminal report and to `evidence.reason` in
  `detect --json`. No part of the credential value, and not its length, appears.
