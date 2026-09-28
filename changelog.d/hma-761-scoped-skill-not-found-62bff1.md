---
type: fixed
issue: 761
---
#### check on a scoped name npm does not have is not measured (#761)

- `check @publisher/skill`, the placeholder in `check --help` and the README,
  or any scoped name npm does not have, printed "Trying as skill
  identifier...", then `MEDIUM RISK` and exit 0. That lookup fetches nothing
  about the skill: it reads the publisher's DNS TXT record and a local
  blocklist, so the band said "measured" about a target nothing was read
  from. It now prints the npm not-found block with the verify URL and exits
  2, as a bare-name miss does, and keeps the publisher record that
  `docs/dns-verification.md` has a publisher read with this command. `--json`
  carries the not-found shape (`found: false`, `errorHint`, `coverage`) plus
  `publisher`, and no `risk`. An identifier on the blocklist still reports
  `CRITICAL RISK` at exit 1.
