---
type: fixed
issue: 316
breaking: true
---
#### secure reports an `sk-` key with a 32 to 47 character body (#316)

- `secure` recognised a hardcoded `sk-` key only when its alphanumeric body
  was 48 or more characters long. A source file holding
  `const openai = "sk-<32 characters>"` scored 93/100 and exited 0. Bodies of
  32 to 47 characters now raise AST-CRED-001 (high) and AST-CRED-003
  (critical), the findings a 48-character key raises, and the same project
  scores 69/100 and exits 1. The finding reads
  `OpenAI-style sk- key: [REDACTED]` and does not print the value.
- A body made of six or fewer distinct characters, such as `sk-` followed by
  32 `x`, is treated as a mask and not reported. Values carrying a marker such
  as `EXAMPLE`, and identifiers such as `task-` or `disk-` followed by a hash,
  stay quiet as before.
