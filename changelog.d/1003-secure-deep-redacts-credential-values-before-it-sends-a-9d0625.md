---
type: fixed
issue: 1003
---
#### `secure --deep` redacts credential values before it sends a file to the probe executor, and four output fixes (#1003)

- `secure --deep` put the full text of each scanned `.md`, `.yaml` and `.yml`
  file into the system prompt of every probe request, so a credential value in
  that file, such as an `api_key:` line in `config.yaml`, reached the probe
  executor. The text and the tool names read from it now pass through the
  redaction `attack` applies to its target. It replaces only the values it
  recognises, for example the value in `api_key: abcd1234efgh` or
  `password=abc` and the user name and password in a URL, and it does not
  recognise every credential: `api_key: abc1234`, `DB_PASS=supersecretvalue`
  and `password: "it's-a-secret-123"` are sent as written, and
  `password=h;unter2` is sent as `password=[REDACTED];unter2`. This holds for
  every output format.
- A scanned file over 1 MiB is now sent no probe by `secure --deep`. The
  redaction withholds content over that size whole, so the probes would have
  seen only the withheld marker. The file is listed with the reason under
  `notSimulated` in the `simulation` block of `--json` and on a `NOT
  SIMULATED` line on stderr, and the block's `status` is `measured` only when
  a probe ran (`not-measured` when every file reached is over the limit).
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
