---
type: fixed
issue: 393
---
#### The Categories line counts every failing finding, not only each category's worst severity (#393)

- `secure` and `check` printed only the highest severity in each category, so a
  high that shared `credentials` with a critical was missing from the line:
  `credentials (1 critical) · git hygiene (1 low)` above a Findings summary of
  `1 critical  1 high  1 low`. Every severity with a finding is now named, worst
  first, for example `credentials (1 critical, 1 high)`, and the counts on the
  Categories line add up to the Findings summary.
