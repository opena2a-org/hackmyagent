---
type: fixed
issue: 891
---
#### `secure` no longer crashes on a `null` entry in a VS Code MCP config (#891)

- A `.vscode/mcp.json` whose `servers` map held a `null` entry made
  `hackmyagent secure` exit 1 with "Cannot read properties of null (reading
  'args')" and print no report. The `null` entry is now skipped, the scan
  completes, and VSCODE-002 still evaluates the other entries in the map.
