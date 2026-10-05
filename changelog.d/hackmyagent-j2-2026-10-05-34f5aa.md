---
type: fixed
issue: 489
breaking: true
---
#### secure -b oasb-2 no longer grades a governance file it did not read (#489)

- Over a tree with no governance file, `secure -b oasb-2` printed
  `Governance Score (OASB-2): 0/100` and `Conformance: NONE` and exited 1,
  and with the infrastructure side measured it averaged that 0 into the
  composite score. `scan-soul` reports the same tree as NOT MEASURED at
  exit 2.
- The governance score, conformance and composite now print as not
  measured, the domain table is replaced by the same NOT MEASURED line and
  search list `scan-soul` prints, and the run exits 2. A zero-byte
  governance file is reported the same way. `--fail-below` is not evaluated
  against the withheld composite.
- `--format json` reports `govScore`, `conformance`, `compositeScore` and
  `govResult` as `null` and adds `govCoverage`, which says whether the
  governance side was measured and why not. A governance file that is read
  and conforms to nothing still fails at `Conformance: NONE`, exit 1.
