---
type: fixed
---
- `secure` no longer reports AST-GOV-002 (weak constraint enforceability) on
  an MCP config or skill for wording that lives in a sibling `SOUL.md`. On
  `test/fixtures/governed-mcp` the finding named `mcp.json`, with no line,
  although `mcp.json` holds none of the "should", "recommended" or "try to"
  wording the fix tells you to change. It is now reported once, on the file
  that holds the wording and at its line (`SOUL.md:39`). The sibling
  `SOUL.md` still counts toward the config's domain coverage and governance
  ratio.
