---
type: fixed
issue: 1024
---
#### Findings, evidence and the text sent to NanoMind replace a quoted password under 8 characters (#1024)

- A quoted value after a password name needed 8 or more characters to be
  replaced in the text of a finding, its evidence, a declared purpose or the
  text sent to NanoMind, so `PASSWORD="abc"` was shown and sent as written.
  A quoted value of any length after `password`, `passwd`, `passphrase`,
  `pwd` or a whole `pass` name segment (`DB_PASS`) is now replaced, quotes
  kept: `PASSWORD="[REDACTED]"`. A short value under `token`, `key`,
  `bypass` or `passthrough` is still shown as written.
