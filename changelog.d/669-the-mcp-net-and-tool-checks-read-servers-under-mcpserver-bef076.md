---
type: fixed
issue: 669
breaking: true
---
#### The MCP, NET and TOOL checks read servers under `mcpServers` as well as `servers` (#669)

- `secure` evaluated MCP-003, MCP-004, MCP-005, MCP-008, MCP-009, MCP-010,
  NET-001, NET-002, TOOL-001, TOOL-002 and TOOL-003 over a root MCP config's
  `servers` map only. In a config that keeps its servers under `mcpServers`,
  the key Claude Code and Cursor read, those checks found no server: MCP-005
  reported nothing for `"allowedTools": ["*"]`, and MCP-009 and TOOL-003
  reported a pass for a server named `shell` running `sh`. They now read both
  keys, and a file that carries both has both maps evaluated.
- TOOL-001 no longer counts a wildcard `allowedTools` (an entry containing
  `*`) as a tool whitelist, and it requires one on each server in the file:
  a file where one server lists tools and another does not now fails, and the
  failure names the server without one. Measured on an MCP project whose
  `servers` config lists tools for one of its two servers: exit 0 at 88/100
  before, exit 1 at 69/100 now. On a `servers` config that grants `["*"]`,
  OASB-1 L1 compliance goes from 63% (5/8) to 50% (4/8).
- TOOL-003 and MCP-009 match whole words of the server name: `execute-shell`
  still fails both, `run_command` still fails TOOL-003, and a server named
  `filesystem` is no longer read as `system`.
