---
type: fixed
issue: 880
---
#### `secure`'s unwritable-report message no longer repeats the `-o` path with raw control characters (#880)

- When `secure --json -o <file>` could not write the report, the message named
  the path escaped and then repeated it raw inside the system error, so a
  control character in the path (an escape sequence, for example) reached the
  terminal. Both copies of the path are now shown escaped.
