---
type: fixed
breaking: true
---
#### Breaking: `wild` reports "not measured" and exits 2 when no attack page answers 2xx

- **Only a page that answered with a 2xx status counts as scanned.** An unreachable
  target, or one where every attack page failed or returned 404, scored `100/100 (strong)`
  and exited 0. It now prints `Wild Resilience: not measured` with the number of pages
  that could not be fetched and the statuses the others returned, gives no score or
  rating, and exits 2 instead of 0, the exit code of every other not-measured result.
- **`--json` carries the same result.** The report has `measured: false`, a
  `notMeasuredReason`, and `null` for `wildResilienceScore` and `resilienceRating`;
  `pagesScanned` counts only the 2xx pages.
- A target that serves at least one attack page scores as before: every fetched page is
  still listed in the report and counted in the score.
- `node dist/index.js <command>` runs the CLI, the same as the `hackmyagent` bin.
  Importing the package is unchanged.
