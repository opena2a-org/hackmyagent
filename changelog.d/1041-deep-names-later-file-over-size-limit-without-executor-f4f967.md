---
type: fixed
issue: 1041
---
#### secure --deep without a probe executor names a later file over the size limit (#1041)

- `secure --deep` with no probe executor (no NanoMind daemon, Ollama or
  `ANTHROPIC_API_KEY`) stopped at the first artifact within the 1048576-byte
  redaction limit, so a file over the limit after it was never named: the
  `--json` `simulation` block had no `notSimulated` entry for it and stderr had
  no NOT SIMULATED line. It was named only on a later run with an executor.
  The run now sends no further probe after the NOT MEASURED line but still
  checks the size of every artifact in the batch, so such a file is listed
  under `notSimulated` and gets its NOT SIMULATED line in the same run.
