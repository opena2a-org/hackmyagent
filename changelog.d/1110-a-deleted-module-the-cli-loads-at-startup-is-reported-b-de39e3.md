---
type: fixed
issue: 1110
---
#### A deleted module the CLI loads at startup is reported by the integrity check with exit 3 (#1110)

- Deleting a `dist/` module the CLI imports at startup, such as
  `dist/explain-registry.js` or `dist/attack/index.js`, made
  `hackmyagent --version` exit 1 with a `Cannot find module` stack trace,
  because the integrity check ran after those imports had loaded. The check
  now runs before the rest of the CLI is loaded, so the run prints
  `INTEGRITY CHECK FAILED`, names the file (`Missing file: dist/explain-registry.js`)
  and exits 3, as the README and the exit-code table state.
- A changed module the CLI imports at startup is not run before the check
  stops the load; before, its code ran and then the check exited 3.
- Deleting `dist/cli.js`, `dist/startup-integrity.js`, the verifier or
  `dist/ui/display-safe.js` still fails at module resolution with exit 1:
  those load before the check runs.
