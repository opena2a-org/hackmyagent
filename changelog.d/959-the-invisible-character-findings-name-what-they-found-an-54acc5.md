---
type: fixed
issue: 959
---
#### The invisible-character findings name what they found, and paths carrying unassigned plane-14 code points print escaped (#959)

- The default `secure` output for UNICODE-STEGO-001 printed general guidance
  and never said which invisible characters the file holds; that appeared only
  in `--json`. The guidance now opens with the detected types, for example
  "This file contains zero-width characters (U+200B-200D)".
- UNICODE-STEGO-001 called U+E0100-E01FF "tag characters", and
  UNICODE-STEGO-004 called U+E0000-E01FF "the Unicode Tag block". The text now
  uses Unicode's names: the Tags block (U+E0000-E007F), the Variation
  Selectors Supplement (U+E0100-E01EF) and the unassigned code points beside
  them. Which files the checks report is unchanged.
- A path or other scanned text containing an unassigned code point in
  U+E0080-E00FF or U+E01F0-E01FF reached the terminal unescaped, so
  `benign` + U+E01F0 + `evil.js` printed as `benignevil.js`. These code points
  are now shown as `\u{e01f0}`, as the Tags block and the variation selectors
  already were.
