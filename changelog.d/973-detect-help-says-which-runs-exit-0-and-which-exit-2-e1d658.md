---
type: fixed
issue: 973
---
#### `detect --help` says which runs exit 0 and which exit 2 (#973)

- The exit-code table said `detect` exits 2 when it finds no AI agent, MCP
  server, AI config or governance file. A run that finds nothing exits 0,
  because the scan ran and found nothing. The table now lists that case
  under 0, and lists the two runs that do exit 2: a directory that does not
  exist or could not be read, and a `--depth` that is not a whole number.
  The exit codes themselves are unchanged.
