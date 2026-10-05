---
type: fixed
issue: 869
---
`secure` no longer drops every Layer-2 semantic finding, and its `semanticAnalysis` summary, when one MCP server entry gives `args`, `allowedTools` or `allowedCommands` a value that is not a list of strings (for example `"allowedTools": 5`). A lone string is read as a one-item list, non-string list items and any other value are ignored, and the rest of the file and tree is still analyzed.
