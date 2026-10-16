---
type: fixed
issue: 669
breaking: true
---
#### `secure` completes on an MCP config whose server `url`, `command` or `allowedTools` has the wrong type (#669)

- A root MCP config with a server whose `url` was not a string, whose
  `command` was neither a string nor a list, or whose `allowedTools` was
  neither a list nor a string (for example `"url": 7` or `"command": 7`)
  ended `secure` with exit 1, no report and an error such as
  `server.url.startsWith is not a function`. That holds under `mcpServers`
  and under `servers`. The field is now skipped, every other server is
  still evaluated, and the scan reports as usual: a config holding only
  such a server under `mcpServers` measured exit 0 at 94/100, with TOOL-001
  failing and naming the server. The exit code changes from 1 to the scan's verdict, so the
  entry is marked breaking.
