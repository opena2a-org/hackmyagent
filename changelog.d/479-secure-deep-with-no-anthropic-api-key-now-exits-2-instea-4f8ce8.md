---
type: changed
issue: 479
breaking: true
---
#### `secure --deep` with no `ANTHROPIC_API_KEY` now exits 2 instead of reporting a pass (#479)
- Before, `secure --deep` (and `--scan-depth deep`) with no `ANTHROPIC_API_KEY`
  skipped the deep analysis tier without a word: the score, the exit code and
  every output channel read as if it had run and found nothing. A failure of
  the deep analysis call outside its per-file loop was absorbed the same way.
- Now the run reports one `SEM-LLM-NOT-ANALYZED` finding (medium) that names
  the cause and how many files the tier would have analyzed, prints that
  reason and the fix on stderr, and exits 2. It counts against the score like
  the per-file `SEM-LLM-NOT-ANALYZED` finding. A critical or high finding still
  exits 1 first. Fix: set `ANTHROPIC_API_KEY` and re-run with `--deep`, or drop
  `--deep` for the static and semantic result.
- A CI job that runs `--deep` without the key and got exit 0 now gets exit 2.
  Runs without `--deep`, and targets with no files for the tier to analyze,
  are unchanged.
