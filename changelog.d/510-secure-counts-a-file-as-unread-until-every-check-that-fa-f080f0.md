---
type: fixed
issue: 510
---
#### `secure` counts a file as unread until every check that failed to read it has read it (#510)

- When two checks failed to read the same file and only the first of them
  read it later, `hackmyagent secure` dropped the file from
  `coverage.unreadableInputs` although the second check never got its
  contents. The same happened when the second failure was raised outside any
  check, and when two walkers failed to list one directory and only the first
  listed it later. The scan now keeps every reader that failed on a path, and
  the path counts as unread while any of them has not read or listed it
  itself. The errno reported is the first counting one among those readers.
  These orderings arise when a file's permissions change while a scan runs.
  On two real trees and on a tree holding a mode-000 file and a mode-000
  directory, the exit code, score, `unreadableInputs`, files examined and
  failed findings are the same as before.
