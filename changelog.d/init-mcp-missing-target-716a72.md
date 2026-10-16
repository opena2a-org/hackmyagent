---
type: fixed
breaking: true
---
#### `init-mcp` refuses a directory that does not exist instead of creating it (#1113)

- `init-mcp <dir>` on a directory that does not exist created it to hold the
  client file it wrote there, and exited 0. Now it creates and writes nothing
  and exits 2, with `NOT MEASURED — <dir> does not exist, so nothing was
  written.` and `Verify: ls -ld <dir>` on stderr. A path that is a file, or a
  directory that cannot be read, ends the same way with `is not a directory`
  or `could not be read` in place of `does not exist`.
- This changes an exit code: `init-mcp` on such a path exited 0 and now exits 2.
