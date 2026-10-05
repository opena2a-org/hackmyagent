---
type: fixed
issue: 866
---
`secure <missing path> --json -o <file>` now writes the not-measured JSON document to `<file>`, as a measured run does, instead of printing it to stdout and creating no file. The run still exits 2.
