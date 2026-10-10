---
type: security
---
#### `check` no longer sends the user name and password in a git URL to the registry

- `hackmyagent check https://<user>:<password>@<host>/<org>/<repo>.git`, run
  from a terminal without `--ci` and with contribution on, published its scan
  to the OpenA2A registry under the name `<user>:<password>@<host>/<org>/<repo>`.
  When that publish failed, it queued the scan under the same name in
  `~/.opena2a/hma-pending-scans.json`, and the next scan `check` shared sent
  it again. The `Cloning ...` line, the report header and Next Steps printed
  the name, and `--json` carried it in `name` and `url`. A clone that failed
  printed the URL as typed in its error line and in the `--json` `target`.
  `check` has published such a name since it first accepted a raw URL, in
  0.16.1. If you ran `check` that way with contribution on, rotate that
  password or token.
- The user name and password now go to `git clone` only. The published and
  queued name is `<host>/<org>/<repo>`, the output and `--json` show the URL
  without them, and a scan an earlier version queued under such a name is
  sent and kept under the name without them. A URL with no user name or
  password is shown and published as before.
