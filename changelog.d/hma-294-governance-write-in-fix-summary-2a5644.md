---
type: fixed
issue: 294
---
#### `secure --fix` names the governance file it rewrote in its fix summary (#294)

- **The harden-soul write now appears in the stdout fix summary.** Reproduced on 0.33.2: a
  directory holding `package.json` and a 7-line `SOUL.md` came out of `secure . --fix` with a
  413-line `SOUL.md`. The write was reported on stderr (`Governance auto-fix: harden-soul
  applied`), but the stdout summary read `Fixed 1 issue (1 verified): [GIT-001] .gitignore`,
  and Next Steps still said `Auto-fix governance: hackmyagent harden-soul .`, the step the
  run had just taken. The summary now carries `Governance file rewritten: SOUL.md -
  harden-soul added 9 sections (+72 controls)`, says the findings and score above it were
  measured before that write and names the re-run that scores the hardened file, and Next
  Steps drops the governance step when the run applied it. The backup and rollback lines now
  also print when the governance write was the run's only change. No finding, score or exit
  code changes. Tests: `__tests__/cli/secure-fix-governance-summary.test.ts`.
