---
type: fixed
issue: 391
---
#### The `Artifacts` line of `check` no longer calls a file `benign` above a HIGH finding on it (#391)

- `hackmyagent check --nanomind` on a `SOUL.md` that tells the agent to do
  whatever a user asks, to hide adjustments it makes to the numbers and to
  skip confirmations printed `Artifacts   SOUL.md  soul · benign · no
  inferred capabilities`, then `Not safe as-is` and four HIGH findings on
  that same file. A `benign` intent label on an artifact the same scan
  raised a HIGH or CRITICAL finding on now reads `unknown`, and `--verbose`
  names the withheld label and the count: `SOUL.md -> benign, contradicted
  by 4 high/critical findings on this artifact`. This is the counterpart of
  the rule that already withholds a `malicious` or `suspicious` label no
  HIGH or CRITICAL finding corroborates. Findings, severities, scores,
  verdicts and exit codes are unchanged.
