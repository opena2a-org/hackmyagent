---
type: fixed
issue: 770
---
#### `scan-soul --deep` releases its local model session before the process exits (#770)

- `scan-soul --deep` could abort after printing its complete report, with
  `libc++abi: terminating due to uncaught exception of type std::__1::system_error: recursive_mutex lock failed: Invalid argument`
  on stderr and exit code 134 in place of 0, 1 or 2. The local model session
  that the semantic pass opens was never released, so it was still open while
  the process shut down. It is now released when the process exits, on the
  text report, on `--json` and when `--fail-below` ends the run.
- Whether this removes the abort has not been measured yet. The abort is
  intermittent and was recorded only on macOS arm64 with `ANTHROPIC_API_KEY`
  set. Until it is, read exit 134 from this command as no verdict.
