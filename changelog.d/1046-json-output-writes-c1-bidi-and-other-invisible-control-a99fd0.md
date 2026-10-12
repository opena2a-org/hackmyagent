---
type: fixed
issue: 1046
---
#### `--json` output writes C1, bidi and other invisible control characters from paths as `\uXXXX` escapes (#1046)

- `JSON.stringify` escapes C0 control characters and leaves DEL, the C1 range
  (U+0080 to U+009F), bidi controls such as U+202E and the line separators
  U+2028 and U+2029 as they are, so a `--json` document printed to a terminal
  carried them raw from a path: in a finding's `file`, in `backupPath` and in
  every other string. Every `--json` and `--format json` document, on stdout
  and in an `--output` file, now writes those code points, and the other
  invisible format characters the text output already escapes, as `\uXXXX`
  escapes. A JSON parser reads them back as the same characters, so the
  values a consumer parses are unchanged. This covers `secure` (including
  `secure -b`), `attack`, `wild`, `eval oracle`, `detect` and every other
  command whose `--json` document goes through the shared JSON writer.
