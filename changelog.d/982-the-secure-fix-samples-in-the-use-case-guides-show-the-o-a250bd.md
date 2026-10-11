---
type: fixed
issue: 982
---
#### The `secure --fix` samples in the use-case guides show the output the tool prints (#982)

- The scan-my-agent and OpenClaw guides showed `FIXED  CRED-001 ...` rows, a
  per-file `Backup: .hackmyagent-backup/<name>.<epoch>` line under each, and a
  closing `Backups saved to` line. `secure --fix` prints none of these. Both
  samples are now real output on the repository's fixtures: a
  `Fixed N issues (N verified):` line, one `✓✓ [ID] file - name` line per fix,
  and one `Backup created:` line naming the run's timestamped backup directory.
