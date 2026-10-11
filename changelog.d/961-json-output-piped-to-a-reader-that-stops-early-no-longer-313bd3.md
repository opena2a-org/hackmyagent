---
type: fixed
issue: 961
---
#### JSON output piped to a reader that stops early no longer ends with an EPIPE stack trace (#961)

- `hackmyagent check-metadata --json | head -5` printed `Error: EPIPE: broken
  pipe, write` with a stack trace and exited 1 once its JSON grew past what
  the pipe holds. The same happened to `secure --json`, `--format sarif` and
  the other reports written in one block when the reader (`head`, `grep -m1`)
  closed the pipe before the end. The command now stops writing when the
  reader has gone and exits with the code it would have exited with anyway:
  0 for `check-metadata`, and for `secure` the exit code its findings set.
