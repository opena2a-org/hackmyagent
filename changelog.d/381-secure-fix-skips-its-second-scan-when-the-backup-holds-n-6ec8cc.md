---
type: fixed
issue: 381
---
#### `secure --fix` skips its second scan when the backup holds no copy (#381)

- Since 0.25.2, `hackmyagent secure --fix` has run a second full scan so the
  score it announces matches the next scan, which also reads the backup
  archive the run just wrote. That scan was supposed to be skipped when the
  archive held no copied file, but the skip test also counted the backup
  candidates that did not exist, so it never skipped. It now checks whether
  the archive contains anything besides its manifest. A run that copied no
  file into its backup and fixed nothing now scans the tree once. The
  announced score is unchanged: an archive holding only its manifest adds
  no finding.
