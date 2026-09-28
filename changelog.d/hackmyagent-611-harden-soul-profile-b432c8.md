---
type: fixed
issue: 611
---
#### `harden-soul --profile` refuses a value that is not a profile (#611)

- **`harden-soul --profile <value>` exits 1 and writes nothing when the value is not one of
  `conversational`, `code-assistant`, `tool-agent`, `autonomous`, `orchestrator` or `custom`.**
  It named the accepted set in `--help` but cast whatever it was given and wrote it into the
  generated file's `<!-- soul:profile=… -->` marker: `harden-soul --profile bogus <dir>` exited 0
  and left `soul:profile=bogus`, a marker `scan-soul` then trusts to decide which governance
  domains apply. The check is in the writer, so the library and the MCP server refuse the same
  values. Accepted profiles are unchanged, case-insensitive as before.
