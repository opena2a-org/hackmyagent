---
type: fixed
issue: 1017
---
#### Steganography Fix commands run from any directory, and `secure --deep` redacts each file once (#1017)

- The `Fix:` command of UNICODE-STEGO-001, -003 and -004 named the file
  relative to the scanned directory, so `xxd tags.js | grep "f3a0"`, printed by
  `secure proj` run from the parent of `proj`, answered `tags.js: No such file
  or directory`. The text output now names the file the way the `Verify:` line
  of the same finding does. The `--json` `fix` field is unchanged.
- `secure --deep` redacted the text of each file and its tool names once for
  every probe sent for that file. It now does so once per file. The text sent
  to the probe executor is unchanged.
