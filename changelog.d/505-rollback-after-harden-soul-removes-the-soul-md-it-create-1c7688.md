---
type: fixed
issue: 505
---
#### `rollback` after `harden-soul` removes the SOUL.md it created (#505)

- When `hackmyagent harden-soul` created a governance file, it printed an
  `Undo: hackmyagent rollback <dir>` line, but `rollback` left the file in
  place. The file is now recorded with its hash, and `rollback` removes it,
  or keeps it and names it when it was edited after `harden-soul` wrote it.
- A `harden-soul` run that changes nothing (every domain already covered, a
  refused write, or a refused `--tier`) no longer leaves an empty backup run
  behind. Before, the next `rollback` undid that empty run instead of the
  run before it. Such a run prints no Undo line.
