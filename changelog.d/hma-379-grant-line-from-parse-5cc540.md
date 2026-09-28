---
type: fixed
issue: 379
---
#### Permission-grant findings in JSON configs cite a line again, from the parse (#379)

- **`detect`'s broad-permissions finding and `secure`'s `CLAUDE-002` now name
  `file:line` for a JSON config**, with a runnable `Verify: sed -n '<line>p' …`. Since #364
  a structured config named only the file, because every text search for the entry could
  land on a `deny` entry holding the same text. The line now comes from the parse:
  `walkConfigForGrants` records the keys and indices it followed to the value it judged, and
  a new locator follows that same path through the raw JSON (JSONC comments and trailing
  commas included, last duplicate key wins as in `JSON.parse`) and checks the value it lands
  on. Any disagreement leaves the line out; it never cites a different one.
- **`CLAUDE-002` gains a `Verify:` line.** It had none, because verify commands need a line.
- **YAML configs still carry no line.** `js-yaml` exposes no per-node positions, and a
  guessed line is worse than none.
- Measured on generated `.claude/settings.json` files whose deny list repeats the granting
  entry: 200KB `detect` 0.36s (0.30s before), `secure` 3.70s (3.56s); 4MB `secure` 3.9s at
  a peak RSS of 215MB (220MB before). `detect` skips config files over 1MB, as before.
  Verdicts, severities and scores are unchanged.
