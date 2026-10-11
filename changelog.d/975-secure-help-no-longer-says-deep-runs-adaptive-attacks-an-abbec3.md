---
type: fixed
issue: 975
---
`secure --help` no longer says `--deep` runs "adaptive attacks", and neither does the `Analysis:` line `secure --deep` prints when the NanoMind daemon is running. `--deep` runs static checks, semantic analysis and the behavioral simulation; no attack stage runs under it.
