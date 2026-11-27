---
type: fixed
issue: 505
---
#### `red-team` quotes a stated rule that wraps across lines on one line (#505)

- A rule the artifact wraps over two lines printed in the surface list with a literal `\n`, for example `delete\n  branches`. Each line break in the quoted rule, with the spaces and tabs around it, now prints as one space, in the text report and in the `surface` field of `--json`. The same statements map to the same surfaces as before, and every other control character in the quote is still shown escaped.
