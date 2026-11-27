---
type: fixed
---
- `secure` reads `.mts` and `.cts` files. Before, only the skill bundle walk
  read them, so a finding in one elsewhere was never reported and the file
  was not counted in `coverage.filesExamined`. The same bytes under `.ts`,
  `.mts` or `.cts` now give the same findings, from the static checks, the
  Unicode steganography checks and the semantic pass, and the file is
  counted as read.
- The 27 source checks (LOG-002, AUTH-003 to AUDIT-004) read every
  JavaScript and TypeScript extension: `.ts`, `.js`, `.mjs`, `.cjs`, `.mts`,
  `.cts`, `.tsx` and `.jsx`. They read only `.ts` and `.js` before. Their
  not-applicable reason reads "No JavaScript or TypeScript files in the
  scanned tree", and its subject lists the extensions read.
