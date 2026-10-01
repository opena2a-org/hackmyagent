---
type: fixed
issue: 671
---
#### `hackmyagent_benchmark` names a failing checkId once (#671)

The MCP benchmark text listed a checkId once per failing record, so a check that failed in
both `mcp.json` and `.mcp.json` read `(TOOL-004, TOOL-004)`. The id list beside `[FAIL]` is
now de-duplicated; control statuses, counts and compliance are unchanged.
