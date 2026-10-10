---
type: added
---
#### A census of attack families and their canonical classes

- `docs/attack-family-census.md` lists every attack family code held by the
  HackMyAgent taxonomy, the agent threat matrix and the OpenA2A Registry, 77
  codes in all, with the one canonical class each belongs to (the class
  `check-metadata --json` reports as `canonicalClass`). Where the three
  registers disagree it names the code: the four codes that fold into a
  family holding the same condition (`MCP-PRIV-ESC` into `MCP-EXPLOIT`,
  `CMD-INJECT` into `CODE-INJECTION`, `PROMPT-INJECT` into `SOUL-INJECT`,
  `PERSISTENCE` into `PERSIST-STATE`), the four `SOUL-HV-00N` spellings of
  `SOUL-HV`, the families each register is missing, and 19 family strings
  that source files set inline and that no register holds.
