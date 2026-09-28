---
type: fixed
issue: 360
---
#### A collapsed group in the default report names the files its findings are in (#360)

- **`+ N more <severity> in <file>` named the printed finding's file, not the folded ones.**
  The default report folds findings that share a name and a directory under the one it
  prints, and the fold line took the printed finding's file name. The same `eval()` in
  `lib/cbom.js`, `lib/scanner.js` and `lib/scanner-tls.js` rendered as `+ 2 more critical in
  cbom.js`, sending the reader to a file holding one of the three. The line now names the
  folded files (`in scanner-tls.js, scanner.js`), counts them past three (`in 5 files`), and
  claims no location when a folded finding has no file. `--verbose` output is unchanged.
