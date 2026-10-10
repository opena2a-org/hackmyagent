---
type: fixed
issue: 937
---
#### `secure --json` repeats a long `.hmaignore` line in at most 1024 characters (#937)

- Each `.hmaignore` rule was repeated as written in `hmaignore.rules[].rule`,
  and its path, check pattern or reason again in `path`, `checkId` or
  `reason`, so a tree whose ignore file carried one 4 MB line produced a
  `--json` report of more than 8 MB. Those fields, `hmaignore.errors[].rule`
  and the line text quoted in an error message now stop at 1024 characters
  and end with `… (<length> characters)`, so the `hmaignore` record of that
  line is about 2 KB.
  The `.hmaignore:<line>` error lines printed in the terminal are bounded the
  same way. Text up to 1024 characters is repeated unchanged, and every rule
  is still applied in full.
