---
type: fixed
issue: 643
---
#### secure reports a wildcard grant written as `"tools": ["*"]` (#643)

- SEM-MCP-004 (wildcard permission in an MCP server) read a server's
  `allowedTools` and `allowedCommands` and skipped its `tools` key, which
  AST-SCOPE-001 already reads as an allow-list. A `.mcp.json` server granting
  `"tools": ["*"]` or `"tools": "*"` raised no SEM-MCP-004. It now raises one
  high finding on the `tools` line, and `secure` scores that tree lower to
  match. A `tools` list of named tools, or of tool-definition objects, is not
  a wildcard and stays quiet.
