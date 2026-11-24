---
type: fixed
issue: 959
---
#### `explain UNICODE-STEGO-004` no longer calls plane-14 characters "tag characters" (#959)

- The fix line of the UNICODE-STEGO-004 definition, which `explain` prints,
  told the reader to locate "the Plane-14 tag characters". The check reports
  all of U+E0000-U+E01FF, of which only U+E0000-E007F is the Tags block; the
  line now says "the invisible plane-14 characters (U+E0000-U+E01FF)", the
  name the finding itself already uses.
