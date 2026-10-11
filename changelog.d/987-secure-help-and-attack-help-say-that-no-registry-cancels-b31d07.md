---
type: fixed
issue: 987
---
#### `secure --help` and `attack --help` say that `--no-registry` cancels `--publish` (#987)

- Both described `--no-registry` as "Skip auto-publishing results to OpenA2A
  Registry", which implied results are uploaded by default. Neither command
  publishes unless a flag asks for it, and on these two commands
  `--no-registry` cancels `--publish` only. The help now reads "Cancel
  --publish for this run (other Registry flags are unaffected)".
