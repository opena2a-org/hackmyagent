---
type: fixed
issue: 645
---
Library API: `SEMANTIC_OASB_MAPPINGS` no longer lists control 5.2 (#645). Its `'5.2': ['SEM-CRED-002']` entry told a library consumer that 5.2 is verified by `SEM-CRED-002`, while the OASB-1 catalogue the assessor reads verifies 5.2 with `MCP-006` and `MCP-009`. The export is documentation of the catalogue, not configuration; a test now holds every entry to a subset of the catalogue's `checkIds`. Benchmark results are unchanged.
