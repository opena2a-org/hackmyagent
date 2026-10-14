---
type: fixed
issue: 1058
---
#### `secure --fix` repeats a long `.hmaignore` rule in at most 1024 characters where it lists a file it left alone (#1058)

- When an `.hmaignore` rule kept `--fix` from writing a file, the rule was
  repeated as written in `fixWritesExcluded[].rule` of the `--json` report
  and in the `Not fixed` line. With a `.env # ` rule followed by 2 MB of
  text, `fixWritesExcluded[0].rule` was 2,097,159 characters and the
  `Not fixed` line 2,097,220. Both now carry at most 1024 characters of the
  rule and end with `… (<length> characters)`, as the `hmaignore` record has
  since #937: the same run reports a 1,046-character `rule` and a
  1,109-character `Not fixed` line. A rule up to 1024 characters is repeated
  unchanged, and the rule still keeps `--fix` from writing the file.
