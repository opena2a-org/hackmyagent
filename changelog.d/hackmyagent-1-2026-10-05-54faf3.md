---
type: fixed
---
#### `wild` no longer stalls on a `robots.txt`, `llms.txt` or `sitemap.xml` that repeats `security` or `ignore`

- `wild` marks each of those files that mentions a security test or asks to
  ignore instructions, and prints an excerpt from the line that does. A file
  that repeated `security ` or `ignore ` on one line without finishing the
  phrase slowed that check with the square of the line's length: 1 MiB of
  `security ` took 48 seconds, and 1 MiB of `ignore ` behind a marked word
  took 61 seconds more for the excerpt. Both now take about a millisecond on
  1 MiB, and they mark the same files and print the same excerpts as before.
