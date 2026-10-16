---
type: fixed
---
- The contribution tip printed after the third interactive scan names a
  command that runs. It read `npx hackmyagent scan --contribute`, and `scan`
  has no `--contribute` option, so following it ended in
  `error: unknown option '--contribute'`. The tip now reads
  `npx hackmyagent secure --contribute`, which shares that scan's anonymized
  findings; `opena2a config contribute on` remains the way to turn sharing on
  for every scan. The test that checks every printed flag against the command
  it is printed for skipped this line because it began with `npx`; it now
  reads `npx`, `pnpm dlx` and `bunx` in front of `hackmyagent` as this tool.
