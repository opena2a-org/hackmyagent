---
type: fixed
issue: 983
---
#### `secure --deep` runs the behavioural simulation in every output format (#983)

- `hackmyagent secure --deep` ran the 20-probe simulation only in text
  output. With `--json`, or `--format sarif`, `html` or `asff`, the same run
  skipped it and printed nothing about it, so the flag did less in CI than in
  a terminal. The simulation now runs whatever the format, and its
  `[Simulation]` lines go to stderr beside the document.
- `--json` carries the result as a `simulation` block, also under
  `-b oasb-1` and `-b oasb-2`: `status` (`measured`, `not-measured`,
  `no-artifacts` or `error`), the `executor` that ran the probes, how many
  artifacts were found and simulated, and for each one the probe count and
  the ids of the probes flagged. The block is advisory: the score, the
  findings and the exit code do not move with it. It is absent without
  `--deep`.
- A `--deep` run in one of those formats with a probe executor present
  (NanoMind daemon, Ollama or `ANTHROPIC_API_KEY`) now sends the probes it
  skipped before, 20 per file, and takes correspondingly longer.
- The run simulates the first 10 `.md`, `.yaml` and `.yml` files it finds.
  Over a larger tree the progress line now reads `10 of <n> artifact(s)
  (limit 10; the rest are not simulated)` where it named all `<n>`, and the
  block reports both counts.
- The README said the simulation "observes what a skill actually does". It
  gives each file to a model as its instructions and reads the replies to the
  probes; the README now says that.
