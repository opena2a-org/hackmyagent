---
type: fixed
issue: 999
---
#### Fix commands for hidden-character findings run as printed, `--publish` keeps stdout to the JSON document, and telemetry under CI says why it is off (#999)

- `UNICODE-STEGO-003` printed a `node -e` command that failed with
  `ReferenceError` when pasted, because the file path closed the shell's
  quotes. The path is now an argument, and the command lists the file's code
  points above U+0200.
- `UNICODE-STEGO-001` and `UNICODE-STEGO-004` printed
  `xxd 'benign\u{e0041}evil.js'` for a file whose name holds an invisible code
  point, naming a file that does not exist. Such a name now gets a sentence
  instead of a command; any other name gets the `xxd` command as before.
- `UNICODE-STEGO-004` is titled "Invisible Plane-14 Characters Detected", which
  matches its description: the Tags block, the Variation Selectors Supplement
  and unassigned code points.
- `--publish` wrote "No signing keys found ..." and "Published to registry ..."
  to stdout, after the document of `attack --json --publish`. Both lines now go
  to stderr.
- Paths and other scanned text print every plane-14 code point escaped,
  including the unassigned ones above U+E01FF, and a variation selector after
  an emoji prints escaped unless it is U+FE0E or U+FE0F. `❤` followed by
  U+E0100 used to print raw.
- Under a CI or test-runner variable, `hackmyagent telemetry on` printed
  `state: on` while the next `telemetry status` printed `state: off`. Both now
  print `state: off` with a `why off:` line naming the variable, and
  `--version` prints the same reason after `Telemetry: off`.
