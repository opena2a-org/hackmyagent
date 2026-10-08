---
type: fixed
issue: 914
---
#### `explain` describes NEMO-005, NEMO-006 and NEMO-007, and no longer suggests a scan for a removed check ID (#914)

- `hackmyagent explain NEMO-005`, `NEMO-006` and `NEMO-007` printed only
  "Static analysis pattern finding." and an attack class, although
  `explain CODEINJ-001`, `TMPPATH-001` and `ENVLEAK-001` send readers to them.
  Each now says what lines the check reports, why that is a risk, and the fix.
- `explain` on a removed check ID (CODEINJ-001, TMPPATH-001, ENVLEAK-001)
  suggested `secure --verbose` to see it in context, though no finding
  carries a removed ID. Its Next Steps block now names the check that
  remains, for example `Remaining check:  hackmyagent explain NEMO-006`.
- The README quick-start sample printed `Surfaces    library · 47 files` and
  `47 files analyzed` beside a Checks line counting 12 semantic artifacts.
  It now reads `12 semantic artifacts` and `12 files analyzed`, the count
  `secure` prints on all three lines.
