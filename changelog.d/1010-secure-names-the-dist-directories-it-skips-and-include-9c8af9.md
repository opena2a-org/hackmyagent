---
type: fixed
issue: 1010
---
#### secure names the dist/ directories it skips, and --include-dist walks them (#1010)

- `secure` skips `dist/` as build output. On an extracted package, where
  `dist/` holds the code that runs, it examined only the README and
  `package.json` and reported the score with nothing to show the code was
  never read (`coverage.examined 2, total 2` on a package with 7 `.js` files
  under `dist/`).
- Each skipped `dist/` is now listed in `coverage.skippedDirectories` in the
  `--json` output, with its path and file count, and printed as a
  `Not walked` line in the text report. Trees without a `dist/` produce the
  same output as before.
- `secure --include-dist` runs the static checks over `dist/` as well. Use it
  on an extracted package.
