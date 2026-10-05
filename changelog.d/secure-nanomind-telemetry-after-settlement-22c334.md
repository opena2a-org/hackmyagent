---
type: fixed
issue: 655
---
#### `secure` sends no NanoMind classification telemetry for a run that exits 2 (#655)

- With contribution consent on, `secure` posted its per-artifact NanoMind
  classification records (content hash, classification, confidence, verdict)
  during the scan, before it settled the exit code, so a run that then exited
  2 (unmeasured) had already sent them. The records now flush after the exit
  code is settled, and only when the run may send anything outbound, the same
  rule `--publish`, the registry reports and the contribution follow. A run
  that exits 2 sends none of them.
