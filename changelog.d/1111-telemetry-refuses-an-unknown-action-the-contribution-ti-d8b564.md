---
type: fixed
issue: 1111
breaking: true
---
#### `telemetry` refuses an unknown action, the contribution tip's cooldown starts only when the tip is shown, and `red-team` prints its governance label in full (#1111)

- `hackmyagent telemetry bogus` printed `Unknown action 'bogus'` and exited 0. The message now goes to stderr and the run exits 1. `telemetry status` still exits 0.
- Three `secure <dir> --json` runs printed no contribution tip, yet the third stored `contributePromptDismissedAt` in the OpenA2A config, which started the tip's 30-day cooldown. The same three runs now count three scans and store no `contributePromptDismissedAt`. The tip's cooldown now starts only on a run that prints the tip: text output to a terminal.
- `red-team <SOUL.md>` printed the truncated label `Governance ment.:`. It now prints `Governance terms:`.
