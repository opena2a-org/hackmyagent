---
type: fixed
issue: 468
breaking: true
---
#### UNICODE-STEGO-005 no longer reports a confusables table in comments or as a lone string entry (#468)

- A homoglyph detector has to carry the letters it detects, so
  UNICODE-STEGO-005 reported HIGH on HackMyAgent's own stego analyzer, under
  its own name or any other, and on any sanitiser or linter that keeps a
  confusables table. A directory holding only such a file made `secure` exit 1.
- In `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs` and `.cjs` files, comments are now
  removed before the search: trailing `//` comments and every line of a
  `/* */` block, not only lines that start with `//`, `#` or `*`.
- A confusable letter is reported when it sits directly next to an ASCII
  letter or digit or forms an identifier outside a string. In these
  examples `<a>` and `<o>` stand for the Cyrillic letters: `"p<a>ypal.com"`,
  `v<a>lidate`, `require("l<o>dash")` and `const <a> = 1` are all still
  HIGH. One standing alone inside a string, such as the value of a lookup
  table, is not reported. A directory holding only such a table now exits 0.
