---
type: fixed
issue: 882
---
`secure <missing path> --format sarif -o <file>` (and `html`, `asp`, `asff`) still writes no file, and now says so: stderr names the file that was not written and points to `--format json -o <file>`, the one format that records a target that does not exist. `secure --help` states the same under `-o`. No SARIF is written for a run that scanned nothing, because a SARIF upload with no results closes a repository's open code-scanning alerts. The run still exits 2.
