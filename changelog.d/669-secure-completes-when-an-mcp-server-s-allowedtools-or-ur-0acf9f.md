---
type: fixed
issue: 669
---
#### `secure` completes when an MCP server's `allowedTools` or `url` is not a list or a string (#669)

- `secure` stopped with `Error: server.allowedTools?.includes is not a
  function` when an MCP server entry gave `allowedTools` an object or a
  number, and with `Error: server.url.startsWith is not a function` when it
  gave `url` a number or an object, and wrote no report. Such an entry now
  declares no tools and no URL: MCP-005, NET-002 and MCP-008 read it as they
  read an entry without the field, TOOL-001 fails it, and the rest of the
  tree is still checked. A string `allowedTools` of `*` still fails MCP-005.
