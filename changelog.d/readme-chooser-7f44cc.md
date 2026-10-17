---
type: added
---
#### The README answers "What do you want to check?" right after Quick start, rendered from `docs/chooser.json`

- The new section lists five things a reader may want to check (their own
  project before shipping it; a package, repository or skill before
  installing it; a running agent endpoint they own; one text, such as a pull
  request body; every agent project under a folder), each with its
  `npx hackmyagent` command and the command to run next. `scan-soul`,
  `red-team` and `scan` are listed under More, and the `red-team` choice reads
  "Attack payloads to run yourself".
- `docs/chooser.json` holds each choice's wording, command, next command and
  a one-line meaning of exit code 1. `node scripts/chooser.mjs --write`
  renders the README section from it, and `node scripts/chooser.mjs --check`
  exits 1 when the section differs from the data and 2 when a marker is
  missing.
- The section sits between Quick start and What it finds. The Scan anything
  table and the "secure vs check vs red-team vs attack" list stay in
  `docs/commands.md`. The section adds 11 lines and 153 words to the README
  (`wc -w`).
