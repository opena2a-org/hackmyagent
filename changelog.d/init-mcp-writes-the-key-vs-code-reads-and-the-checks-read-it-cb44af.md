---
type: fixed
---
#### `init-mcp` writes the key VS Code reads, and the checks read it back

- **`init-mcp` for VS Code writes `servers`, not `mcpServers`.** The VS Code
  target wrote its entry into `.vscode/mcp.json` under `mcpServers`; the
  workspace file's top-level key is `servers`, which is also the key this
  tree's own reader of that file, VSCODE-002, has always walked. Writer and
  reader disagreed inside one release: `hackmyagent secure` could not see the
  VS Code entry `hackmyagent init-mcp` had just written. The entry now goes
  under `servers`, other entries there are untouched, and a stale
  `mcpServers.hackmyagent` an earlier release left in that file is moved to
  `servers` on the next run rather than left as a second, inert server — the
  #463 repair discipline, applied to a key instead of an argument. Nothing an
  existing user had stops working: a `.vscode/mcp.json` written by any release
  through 0.33.2 carried an entry VSCODE-002 never saw.
- **`--tool vscode` resolves.** The spelling `init-mcp --help` advertises
  (`Force specific tool: claude, cursor, vscode`) threw `Unknown tool: vscode`,
  because the matcher asked whether `vs code` contains `vscode`. Tool names are
  now matched with separators dropped, so `vscode`, `vs code` and `VSCode` all
  reach the VS Code target and an unknown name still throws `Unknown tool:`.
- **MCP-001 reads `mcpServers` in `.mcp.json`.** #637 put `.mcp.json` into the
  root config discovery set, but the walk inside it was `servers` alone, so a
  filesystem server scoped at `/` in the file Claude Code actually reads — the
  file `init-mcp` writes — was read and then reported nothing. Both spellings
  are now walked, in `mcp.json` and `.mcp.json` alike, and `secure --fix`
  rewrites a `/` argument there as it always has under `servers`. The Layer-2
  MCP analyzer gains the same parity: server entries under `servers` are
  evaluated exactly as entries under `mcpServers`, so `.vscode/mcp.json` stops
  reaching it as an empty server map.
- Which file and key each client loads is now ONE exported constant
  (`src/mcp-clients.ts`), consumed by the writer and by the checks that read
  those files; the Claude Code target is one of `ROOT_MCP_CONFIG_FILES`.
  Regression: `__tests__/cli/init-mcp-vscode-servers-key.test.ts`,
  `__tests__/mcp-client-targets-contract.test.ts`,
  `__tests__/hardening/mcp-001-reads-mcpservers.test.ts`,
  `__tests__/semantic/mcp-config-servers-key.test.ts`,
  `__tests__/repo/hma-71-client-config-docs.test.ts`.
