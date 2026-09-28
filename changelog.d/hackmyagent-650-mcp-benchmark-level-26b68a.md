---
type: fixed
issue: 650
---
#### The MCP `hackmyagent_benchmark` tool refuses a level outside L1-L3 (#650)

- **A `level` other than L1, L2 or L3 returns `Error: Invalid level 'L9'. Use: L1, L2, or L3`,
  the line the CLI prints for `-b … -l L9`, before any scan runs.** The MCP server does not
  enforce the tool schema's enum, so `L9` reached the rating ladder and returned
  `RATING_LADDER[level] is not iterable`. An explicit empty level is refused rather than read as
  L1, as the CLI refuses `-l ''`. The exported `assessBenchmarkFindings` refuses an invalid level
  on its own. Valid levels, in either case, and the L1 default are unchanged.
