---
type: fixed
issue: 757
---
#### `init-mcp` writes the file Claude Code reads

- **`init-mcp` for Claude Code writes `<dir>/.mcp.json`.** The Claude Code
  target wrote the `mcpServers` block into `.claude/settings.json`, which Claude
  Code does not read for project MCP servers: after `init-mcp -t claude`,
  `claude mcp list` printed `No MCP servers configured` and the advertised
  tools were never reachable (#757; the identical object in `.mcp.json` lists
  the server). The target is now `.mcp.json`; an existing `.mcp.json` is
  detected as Claude Code and merged, and the success line names the file that
  was written. Cursor (`.cursor/mcp.json`) is unchanged; the VS Code file is
  corrected in the entry below, which changes the key written into it. A block
  that an earlier release left in `.claude/settings.json` is inert and can be
  deleted by hand; this release does not edit that file.
  Regression: `__tests__/cli/init-mcp-claude-code-writes-mcp-json.test.ts`.
