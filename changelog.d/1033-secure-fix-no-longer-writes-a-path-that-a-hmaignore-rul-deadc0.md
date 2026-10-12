---
type: fixed
issue: 1033
---
#### secure --fix no longer writes a path that a .hmaignore rule excludes (#1033)

- With a `.hmaignore` rule such as `fixtures/`, `secure --fix` used to rewrite
  files under `fixtures/`, for example replacing a credential in
  `fixtures/config.json`, while the report left that finding out of scope. A
  fix now never writes a file a whole-path rule covers, or a file a
  `<path>:<CHECK>` rule covers for the check being fixed. That includes the
  PERM-001 permission change, the governance file harden-soul writes, and a
  link inside the tree that resolves into an excluded path.
- Each write left undone is listed under `Not fixed` with its path, the
  `.hmaignore` line and rule that excluded it, and the checks it would have
  fixed. `--json` carries the same list as `fixWritesExcluded`. A refused
  write is not reported as FIX-WRITE-FAILED, and a credential fix that was not
  written no longer adds its variable to `.env.example`.
