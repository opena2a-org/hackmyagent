---
type: fixed
---
- `scan-soul`, `harden-soul` and `secure -b oasb-2` read a
  `<!-- soul:tier=… -->` marker in time proportional to the size of the
  governance file. A run of the opener `<!--soul:tier=` repeated with no
  whitespace and no closing `-->` made the marker pattern go back over the
  rest of the run for every opener, so the scan time grew with the square of
  the run's length. Which marker is honoured is unchanged.
