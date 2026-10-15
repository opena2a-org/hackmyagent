---
type: fixed
breaking: true
---
#### NEMO-008 does not read an export list as a verify step, or a regular-expression `exec` call as running a process

- NEMO-008 (`TOCTOU race between verify and apply`, HIGH) pairs a line that
  matches `verify ... digest`, `validate ... hash` or `check ... integrity`
  with a line that calls `exec(`, `spawn(`, `execSync(` or `execFile(` in
  another file of the same directory. It paired the CommonJS export list
  that `tsc` writes for a barrel file, such as
  `exports.validateToken = exports.formatDate = exports.hashName = void 0;`,
  where `validate` and `hash` are parts of two exported names, with a
  regular expression's `.exec(text)` in a sibling test file. A directory
  holding only those two files scored 69/100 and `secure` exited 1.
- A line that is only an export or import list is not read as a verify
  step: `exports.a = exports.b = void 0;`, `export { a, b }`, an
  `import ... from` or `export ... from` line, and `module.exports = { a, b }`.
  A `.exec(` method call is read as running a process only in a file that
  imports `child_process` (`require('child_process')`,
  `require('node:child_process')`, `from 'child_process'` or
  `from 'node:child_process'`). A bare `exec(` call, and `spawn(`,
  `execSync(` and `execFile(`, are read as before. The directory above now
  scores 98/100 and `secure` exits 0. On a TypeScript package whose `tsc`
  output directory held both lines, `secure` went from 69/100 and exit 1 to
  95/100 and exit 0.
- `verify(file, digest)` in one file and a `child_process` `execFile(file)`
  call in another file of the same directory are still reported at HIGH, at
  the verify line, and `secure` exits 1.
- A `.exec(` call on a library other than `child_process`, such as
  `shell.exec(cmd)` from shelljs, in a file with no `child_process` import,
  is not read as running a process, so NEMO-008 does not pair it with a
  verify line.
