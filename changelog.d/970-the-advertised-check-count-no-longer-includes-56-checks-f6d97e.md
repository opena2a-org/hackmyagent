---
type: fixed
issue: 970
---
#### The advertised check count no longer includes 56 checks that no command can report (#970)

- `secure --help`, the `Checks` line of a scan, the `hackmyagent_scan` MCP
  tool description, `check-metadata` and the docs counted 56 check IDs that no
  command reports. PARSE-001..010, FAKETOOL-001..010, PERSIST-004..010 and
  ASKILL-002 have no detector. The 28 HMA-NMC IDs come only from the
  NemoClaw runtime checks, which no command runs. The counts are now 261
  static checks across 67 categories (306 checks across 82 categories
  including the NanoMind semantic layer), down from 317 and 71 (362 and 86).
  Nothing a command reports was removed: findings, severities, scores and
  exit codes do not change.
- `check-metadata --json` reports `totalChecks: 306`, and its `checks` map
  lists those 306. The 56 IDs move to a new `notCounted` array, one entry per
  family with the reason it is not counted. `explain` still answers each of
  them.
- `secure-nemoclaw --help` no longer lists NVIDIA key, network, process and
  sandbox checks it never ran. It says the command runs the `secure` checks on
  the NemoClaw directory, the NEMO-* configuration checks among them, and not
  the runtime checks.
