---
type: fixed
issue: 355
---
#### LIFECYCLE-008 no longer reports "no safety instructions" when the SOUL.md is in a subdirectory (#355)

- `secure` reported LIFECYCLE-008 at CRITICAL ("components
  assembled with no safety instructions") for a tree with `mcp.json` and
  `config.json` at the root and its `SOUL.md` one directory down, such as
  `agent/SOUL.md`. The finding asserted that no SOUL.md or system prompt
  existed while the tree held one.
- LIFECYCLE-008 now fires only when a walk of the whole tree finds no
  `SOUL.md`, `SOUL.yaml`, `system-prompt.md`, `system-prompt.txt`,
  `system_prompt.md` or `persona.md` in any subdirectory (outside
  `node_modules` and `.git`). If a directory cannot be
  listed, the check does not report absence; the directory is reported as an
  unread input instead.
