---
type: fixed
issue: 912
---
#### `red-team` reads the artifact type from the file name, not the folders around it (#912)

- `red-team` matched `soul` or `mcp` anywhere in the target's path, so a
  `SKILL.md` inside a folder such as `mcp-servers/` or `soulful/` was
  reported as `mcp_tool` or `soul` in `target.artifactType` and on the
  `Target:` line. The type now comes from the file name alone: `SOUL.md` is
  `soul`, `mcp.json` is `mcp_tool`, and `SKILL.md` is `skill` wherever it is.
