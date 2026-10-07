---
type: fixed
issue: 470
breaking: true
---
#### `secure` and `check` report an MCP server rooted at a Windows drive or at `/root` (#470)

- SEM-MCP-001 (overprivileged MCP server scope) now reads a Windows drive
  root (`C:\`, `C:/` or `C:`) as critical, like `/`, and `/root`, the root
  user's home directory, as high, like `/home/<user>`. A config whose
  filesystem server was rooted at either raised no SEM-MCP-001 before. The
  finding is cited at the argument line and names a narrower path as the fix.
  A path below either root, such as `C:\projects\app` or `/root/project`, is
  not reported. A run on a config rooted at either now exits 1.
- The known gap disclosed in 0.28.0 is closed. A filesystem server rooted at
  `/`, with no tool key and nothing else wrong in the file, scored 96/100,
  "Usable with caveats", exit 0 under `check`. `check <dir>` now reports it
  as SEM-MCP-001 CRITICAL at the argument line, exits 1 and gives the same
  score as `secure <dir>`. The same server rooted at `./docs` is not reported.
