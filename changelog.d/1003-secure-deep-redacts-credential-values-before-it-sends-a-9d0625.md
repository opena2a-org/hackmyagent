---
type: fixed
issue: 1003
---
#### `secure --deep` redacts credential values before it sends a file to the probe executor, and four output fixes (#1003)

- `secure --deep` put the full text of each scanned `.md`, `.yaml` and `.yml`
  file into the system prompt of every probe request, so a credential value in
  that file, such as an `api_key:` line in `config.yaml`, reached the probe
  executor. The text and the tool names read from it now pass through the
  redaction `attack` applies to its target, and the value is sent as
  `[REDACTED]`. This holds for every output format.
- `check <git URL>` printed `Error: Fetching "<URL>" timed out.` for a clone
  that failed for another reason, such as an authentication failure, when the
  user name, password or path of the URL held the word `timeout` or `Timeout`.
  The word is now read from what git wrote, with the URLs and quoted paths in
  it taken out. The exit code (2) is unchanged.
- `eval oracle --format json` wrote `Running oracle eval against: <dir>` to
  stdout before the JSON document, so the output did not parse as JSON. The
  line now goes to stderr, in both formats.
- `eval oracle --help` listed `skill, soul, mcp or arp-input` as the values of
  `surface`. It now also lists `training-sample`, `veil-payload` and
  `aiis-signature`, and says that those are counted only in the overall row.
- `secure --json` marked SKILL-020 and SKILL-024 findings `"fixable": true`,
  and `secure --fix --dry-run` counted them as auto-fixable, while `secure
  --fix` writes no fix for either. Both now say `"fixable": false`; the
  `fix` text still describes the change to make by hand.
