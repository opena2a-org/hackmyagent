---
type: fixed
issue: 993
---
#### The attack family census counts the families the taxonomy holds now (#993)

- `docs/attack-family-census.md` said the HackMyAgent taxonomy holds 75
  family codes, a count taken before the four `SOUL-HV-00N` controls merged
  into `SOUL-HV`. It now says 72, the count
  `hackmyagent check-metadata --json` reports, and lists `SOUL-HV-001` to
  `SOUL-HV-004` under `SOUL-HV`.
