---
type: fixed
issue: 1024
---
#### Findings and evidence replace a quoted credential value that holds a quote character (#1024)

- A quoted value after a `password`, `secret`, `token` or `key` name in the
  text of a finding, its evidence or a declared purpose ended at its first
  quote character of either kind. `password: "it's-a-secret-123"` was shown
  as written, and `secret = "abcdefgh'ijklmn"` was shown as
  `secret =[REDACTED]ijklmn"`. The value now ends at the quote that opened it,
  so it may hold the other quote character, a `\"` escape or a doubled `''`,
  and is replaced whole. A quoted value with a space in it is still shown as
  written. The text sent to NanoMind is redacted the same way.
