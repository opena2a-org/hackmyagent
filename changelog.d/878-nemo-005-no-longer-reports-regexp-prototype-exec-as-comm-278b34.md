---
type: fixed
issue: 878
---
#### NEMO-005 no longer reports `RegExp.prototype.exec` as command injection (#878)

- `hackmyagent secure` reported NEMO-005 ("exec() with user-controlled string
  interpolation") at CRITICAL on a line such as
  `` new RegExp(`^${name}:\\s*(.*)$`, 'm').exec(block) ``, because the call is
  named `exec` and the line carries an interpolated template literal. A
  regular expression's `exec` runs a pattern match and starts no process.
  NEMO-005 now leaves a line alone when every `exec(` call on it is made on a
  `new RegExp(...)` expression, a regex literal, or an identifier declared
  from one and never assigned, imported or required as anything else.
- `child_process` `exec` and `execSync` calls with an interpolated string are
  still reported at CRITICAL with their `file:line`, including when they share
  a line with a regular-expression `exec`.
