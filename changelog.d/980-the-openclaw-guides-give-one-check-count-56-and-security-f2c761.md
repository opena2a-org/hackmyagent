---
type: fixed
issue: 980
---
#### The OpenClaw guides give one check count, 56, and SECURITY_CHECKS.md lists every OpenClaw check (#980)

- The OpenClaw use-case guide and its row in `docs/USE-CASES.md` said 34 OpenClaw checks, while
  `docs/SECURITY_CHECKS.md` said 47. All three now say 56: the number of check ids the OpenClaw
  checks in `hackmyagent secure` emit.
- The OpenClaw tables in `docs/SECURITY_CHECKS.md` now include SKILL-018 to SKILL-025 and
  HEARTBEAT-007, which the scanner emitted but the tables did not list. The auto-fix table adds
  SKILL-019 and HEARTBEAT-007, which `--fix` re-signs.
- The guide now says the OpenClaw checks are part of the 317 static checks, not added to them.
