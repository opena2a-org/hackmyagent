---
type: fixed
---
- The string-literal test that NEMO-002, NEMO-009 and LOG-002 use to tell
  code from text reads a long line to its end: a real `eval(…)`,
  `new Function(…)`, `JSON5.parse`, `console.log(password)` or digest skip
  after more than 100,000 characters of string, comment or template literal
  on the same line is reported, and a mention inside a string literal there
  is still read as text. The walk is linear in the line, and where the
  scanner cannot tell code from text, it reports.
