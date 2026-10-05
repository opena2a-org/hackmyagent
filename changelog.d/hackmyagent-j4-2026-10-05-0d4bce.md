---
type: fixed
issue: 863
---
#### `explain SOUL-VIOLATION` answers the id `scan-soul --ci` leads with (#863)

- On a governance file with a violation, `scan-soul --ci` ends with a stderr line that starts
  `SOUL-VIOLATION HIGH:`, while `explain SOUL-VIOLATION` answered `Unknown check ID` and exited 1.
  `explain SOUL-VIOLATION` now describes the violation family, lists the per-class
  `SOUL-VIOLATION-*` ids from the scanner's catalog and exits 0. The test that collects every
  `SOUL-*` id from `scan-soul`'s output now also runs it with `--ci`.
