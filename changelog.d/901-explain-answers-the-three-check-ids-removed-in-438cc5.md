---
type: fixed
issue: 901
---
#### `explain` answers the three check IDs removed in #395 (#901)

- `explain CODEINJ-001`, `explain TMPPATH-001` and `explain ENVLEAK-001`
  answered `Unknown check ID`, suggested unrelated checks such as AUTH-001
  and exited 1. Each now says the check is removed, that a `.hmaignore`
  entry for it matches no finding, and names the check that remains
  (NEMO-005, NEMO-006 or NEMO-007), and exits 0.
- The README quick-start sample shows the `Checks` line in the form `secure`
  prints: `317 static declared · 63 of 63 check groups ran · ...`.
