---
type: changed
---
- `SOUL-HV-001` to `SOUL-HV-004` now report the attack family `SOUL-HV` in
  `check-metadata --json` and in `explain`. Before, each id was reported as
  its own family (`SOUL-HV-001` for `SOUL-HV-001`, and so on), which made
  four families out of the four Harm Avoidance controls.
