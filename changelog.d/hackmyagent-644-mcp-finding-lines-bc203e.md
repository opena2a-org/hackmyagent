---
type: fixed
issue: 644
---
#### SEM-MCP-004, SEM-MCP-007 and SEM-MCP-008 findings carry a line (#644)

- **The MCP findings that name a server entry now say where it is.** `SEM-MCP-004` (wildcard
  `allowedTools` / `allowedCommands`) cites the wildcard field inside that server's entry,
  `SEM-MCP-007` (typosquatted package) the package argument, and `SEM-MCP-008` (curl|sh
  bootstrap) the server's key. They were located by file only, in the terminal, in SARIF and in
  an IDE. The lines come from one structural pass over the file: a key counts only at its
  depth, so a server named `command` or `fs` is not found at another entry's `"command"` or
  `env` key, a repeated key resolves to the entry `JSON.parse` kept, and a file of thousands of
  servers is read once rather than once per finding. The server name is matched in its
  JSON-encoded form. A key written differently in the raw text (a `\u` escape) gets no line
  rather than a wrong one. Scores, severities and finding counts are unchanged; measured on a
  three-server fixture, `secure --json` gave 44/100 with 11 failing findings before and after.
