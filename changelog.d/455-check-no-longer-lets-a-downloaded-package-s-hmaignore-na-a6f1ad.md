---
type: fixed
issue: 455
---
#### `check` no longer lets a downloaded package's `.hmaignore` narrow its own audit (#455)

- `hackmyagent check <package>` read `.hmaignore` from the tree it had just
  downloaded: a cloned GitHub repository, an extracted npm or PyPI archive,
  or a file or archive fetched from a URL. A package that shipped an
  `.hmaignore` naming the file holding a hardcoded credential had that file
  left out of the report, the score and the exit code, so the package under
  evaluation chose the scope of its own evaluation. On a test package with
  one hardcoded credential, `check` reported 95/100 and exited 0; it now
  reports the critical finding, 69/100, and exits 1, the same result as for
  the package without the file.
- An `.hmaignore` in a local directory you point `check` or `secure` at is
  still honoured and still disclosed, because there you wrote it yourself.
