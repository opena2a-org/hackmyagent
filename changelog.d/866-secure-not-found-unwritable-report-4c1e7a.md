---
type: fixed
issue: 866
---
#### `secure <missing path> --json -o <file>` still exits 2 when the file cannot be written (#866)

- When the `-o` path cannot be written (its directory does not exist, or is
  read-only), the run names the reason on stderr, prints the not-measured JSON
  document on stdout and exits 2. An unwritable report file does not turn
  "not measured" into exit 1, which means a measured run found a critical or
  high issue.
