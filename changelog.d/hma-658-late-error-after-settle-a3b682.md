---
type: fixed
issue: 658
breaking: true
---
#### `check`: an error after the verdict settled no longer reads as an unmeasured run (#658)

- **One run settles one verdict.** The PyPI, raw-URL, GitHub and npm arms of `check` settle
  the verdict before rendering (#373), but each arm's catch spans the whole arm, so a throw
  from the report renderer or the post-report pending-scan I/O landed in the fetch-failure
  handling. Measured on main before this change with a local URL fixture and a renderer that
  throws at its first section header: the report started, `NOT MEASURED — … was fetched but
  could not be analyzed` printed under it, and the run exited 2 where the same run without the
  throw exits 0; the telemetry event, once-only and already posted at the settle for a
  non-zero verdict, carried the pre-raise code. The GitHub and npm arms classified such a
  throw by its message text (a not-found block when it contained `not found`, and for npm a
  fall-through to the skill lookup when it contained `404`) and assigned exit 2. Now each catch checks the settled verdict first, prints
  `Error after the verdict was settled (exit N stands): <message>` and leaves the exit code
  alone; a failure before the settle is handled as before. Regression:
  `__tests__/cli/check-late-error-after-settle.test.ts` (the faulted URL run exits with the
  unfaulted run's code and prints no `NOT MEASURED`; every settle inside each arm's `try`
  records the verdict and each catch reads it first).
