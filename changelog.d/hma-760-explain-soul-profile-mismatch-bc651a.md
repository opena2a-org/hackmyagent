---
type: fixed
issue: 760
---
#### `explain` answers every id `scan-soul` prints (#760)

- `scan-soul` printed `SOUL-PROFILE-MISMATCH` as a HIGH while `explain SOUL-PROFILE-MISMATCH`
  answered `Unknown check ID` and exited 1. The same held for `SOUL-PROFILE-MARKER-INVALID`,
  the six `SOUL-VIOLATION-*` classes and the `SOUL-CONFORMANCE NONE` line. `explain` now answers
  each of them with exit 0; the violation entries are built from the scanner's own catalog, so a
  new violation class is explainable when it ships. A test collects every `SOUL-*` id from
  `scan-soul`'s text output on two fixtures and runs `explain` on each.
