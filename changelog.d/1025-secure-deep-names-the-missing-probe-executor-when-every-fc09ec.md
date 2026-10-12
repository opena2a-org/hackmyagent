---
type: fixed
issue: 1025
---
#### secure --deep names the missing probe executor when every file is over the size limit (#1025)

- `secure --deep` on a tree whose every artifact is over the 1048576-byte
  redaction limit gave a simulation `reason` that named only the size limit,
  even when no probe executor (NanoMind daemon, Ollama or `ANTHROPIC_API_KEY`)
  was available. A user who shrank the file then met a second "not simulated"
  result. The `reason` now names both causes when both hold, and the progress
  output adds the `NOT MEASURED` line for the missing executor.
