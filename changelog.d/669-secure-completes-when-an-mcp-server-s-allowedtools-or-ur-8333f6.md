---
type: fixed
issue: 669
---
#### `secure` completes when an MCP server's `allowedTools` or `url` has another type, and TOOL-001 escapes the server names it quotes (#669)

- `secure` stopped with `Error: server.allowedTools?.includes is not a
  function` or `Error: server.url.startsWith is not a function`, exit 1 and no
  report, when a server in a root `mcp.json` or `.mcp.json`, under
  `mcpServers` or `servers`, gave `allowedTools` or `url` a number or an
  object. Such a value now declares no tool and no remote, and the other
  servers, the rest of the file and the rest of the tree are still checked
  (MCP-005, MCP-008 and NET-002).
- TOOL-001's failure quotes the servers that lack a tool list. A control
  character in a server name is now shown escaped (`\e[2J`), not sent to the
  terminal, and a name longer than 60 characters is cut to 57 and ends in
  `...`.
