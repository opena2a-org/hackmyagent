---
type: fixed
issue: 1024
---
#### `check --json` reports a contradicted `benign` intent as `unknown`, as the text output does (#1024)

- `check --json` wrote `nanomindIntent.classification: "benign"` on a HIGH
  finding whose artifact the text `Artifacts` line labelled `unknown`,
  because this scan raised HIGH or CRITICAL findings on that file. The
  finding's `nanomindIntent.classification` now reads `unknown` there too,
  and carries `rawClassification: "benign"` and `contradictedBy`, the number
  of HIGH and CRITICAL findings on the artifact.
