---
type: fixed
issue: 516
---
#### `secure --static-only` no longer passes a tree holding a file it could not read (#516)

- At `--scan-depth quick`, `--static-only` turned off the only component that
  finds and opens source files, so a tree holding an unreadable file scored
  98/100 at exit 0 with nothing named. The same tree without the flag, or at
  standard depth, exited 2 and named the file.
- `--static-only` still runs no semantic analysis, but it now finds the same
  files and checks whether each one can be opened. A file that cannot be opened
  is named by `SCAN-UNREAD-001` and counted in `coverage.unreadableInputs`, and
  the run exits 2 at every depth, with or without the flag. A readable tree
  keeps its score and exit code, and `filesExamined` does not change.
