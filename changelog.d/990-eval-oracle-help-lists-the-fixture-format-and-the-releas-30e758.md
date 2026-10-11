---
type: fixed
issue: 990
---
#### `eval oracle --help` lists the fixture format and the release-gate thresholds (#990)

- The help ended "See: hackmyagent-redteam-oracle/METHODOLOGY.md for fixture
  format and release-gate thresholds", a file that is in neither the
  repository nor the installed package, so nothing a user could read named a
  `label.json` field or a threshold. `eval oracle --help` now prints both
  after its options: the `label.json` fields and the values each accepts,
  what is scanned for each surface, and the recall, precision and F1 the
  release gate requires. `eval --help` no longer cites the file.
