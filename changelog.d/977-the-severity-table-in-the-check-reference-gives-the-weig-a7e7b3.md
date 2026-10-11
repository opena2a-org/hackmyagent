---
type: fixed
issue: 977
---
#### The severity table in the check reference gives the weights the score is computed from (#977)

- `docs/SECURITY_CHECKS.md` listed a flat deduction per finding (Critical -15,
  High -10, Medium -5, Low -2), which is not how `secure` scores: a scan with
  1 critical, 3 high, 4 medium and 1 low finding from different checks, none of
  them governance, added up to 33 by the table and scores 50. The table now
  gives the weights the scanner uses
  (25, 15, 8, 3) and the formula they feed, `round(100 * exp(-sum / 150))`,
  with the 0.4 weight for governance findings, the 0.1 weight for findings past
  the third from one check, the cap at 69 while a critical or high finding is
  open, and worked examples.
