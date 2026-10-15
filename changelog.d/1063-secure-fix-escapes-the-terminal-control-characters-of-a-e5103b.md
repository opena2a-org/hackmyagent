---
type: fixed
issue: 1063
---
`secure --fix` escapes the terminal control characters of an `.hmaignore` rule it quotes on stderr when the rule keeps it from rewriting a governance file. The `excluded by .hmaignore:<line>` reason under `Governance auto-fix: NOT applied` wrote the rule as is, so an ESC or BEL byte in the rule reached the terminal. It now shows them as `\e` and `\x07`, as the `Not fixed` line in the report already did.
