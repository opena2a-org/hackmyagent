---
type: fixed
issue: 647
---
#### `secure -o <file>` with the text format is refused instead of ignored (#647)

- **`-o/--output` with the text format (the default) now exits 1 before any scan**, on the
  ordinary arm and with `-b oasb-1` or `-b oasb-2`. No text arm wrote the file: the report went
  to stdout, no file appeared, and nothing said so. The message names `--format json -o <file>`
  and redirecting stdout. json, sarif, html, asp and asff still write the file; the `-o`
  description in `secure --help` now names those formats.
