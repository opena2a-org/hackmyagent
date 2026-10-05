---
type: added
issue: 537
---
#### `secure --range` and `secure --staged` report only what a change introduces (#537)

- `secure` could only scan a whole tree, so as a pull request check it failed on
  every finding the repository already had, including on pull requests that
  changed nothing related. `secure --range <base>..<head>` (or
  `<base>...<head>` to measure from the merge base) now reads both trees from
  git, scans them with the same options, and reports only the findings the base
  does not already have: same check, same file (followed through renames), and
  same cited line content. A file the range deletes reports nothing.
  `secure --staged` does the same for the index against `HEAD`, for a
  pre-commit hook. The score, the exit code and every `--format` cover the
  introduced findings only; `--json` adds a `changeScope` object with the
  commits compared and the `introduced` and `preExisting` counts.
- The flags are refused with `--fix`, `--dry-run`, `-b`, the publish flags and
  `--contribute`, and on a single-file target or a directory outside git.
