---
type: fixed
issue: 869
---
#### `secure` completes when an MCP server's `args` is not a list (#869)

- `secure` stopped with `Error: server.args.findIndex is not a function` and
  wrote no report when one MCP server entry gave `args` a string, a number or
  an object. Such an entry now declares no arguments, and the other servers,
  the rest of the file and the rest of the tree are still checked.
