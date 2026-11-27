---
type: fixed
breaking: true
---
#### `check --no-scan` exits 1 on a Blocked or Warning answer, and tells "not found", "unknown" and "could not ask" apart

- `check <name> --no-scan` exited 0 whatever level the registry gave. It now
  exits 1 when the level is Blocked (0 of 4) or Warning (1 of 4), and shows
  the level as its word beside its number, for example `Scanned (3 of 4)`.
  `check --help` lists which exit code means which outcome.
- When the registry could not be asked (a network failure, a timeout, a 429 or
  a server error), the `--json` document no longer says `"found": false`. It
  carries `"state": "registry-error"`, a `registryError` naming what happened,
  `errorClass` `registry-rate-limited` for a 429 (`registry-unreachable`
  otherwise) and, for a 429 with a Retry-After header, `retryAfterSeconds`.
  The text says in one sentence that the registry could not be asked, and how
  long to wait.
- An answer whose package id is all zeros is shown as not found, with no level.
  An answer with no trust level, or one outside 0 to 4, is shown as `unknown`
  (exit 2) where it used to be shown as Blocked; its JSON `trustLevel` is
  `null` and `trustLevelName` is `unknown`.
- `check <npm name> --no-scan` for a name the registry does not know prints the
  not-found block and exits 2 without running `npm pack`. It used to download
  the package, and scan it when npm had it.
