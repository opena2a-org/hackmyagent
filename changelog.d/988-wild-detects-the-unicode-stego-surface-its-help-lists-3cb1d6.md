---
type: fixed
issue: 988
---
#### `wild` detects the unicode-stego surface its help lists (#988)

- `wild --help` listed `unicode-stego` among the injection surfaces it
  detects, but no detector existed, so a page hiding a payload in invisible
  characters scored as clean.
- `wild` now decodes two encodings from the raw HTML, attributes and comments
  included: Unicode tag characters (U+E0020 to U+E007E), and runs of 8 or more
  zero-width characters drawn from exactly two symbols, read as binary with
  both bit assignments tried. A `unicode-stego` surface is recorded only when
  the decoded text reads as an injection payload, by the same test the other
  surfaces use.
- The invisible characters alone are never reported: Persian ZWNJ, Hebrew
  U+FEFF and bidi marks, emoji ZWJ sequences and subdivision flags such as
  Scotland's produce no surface. Measured on 36 public pages (18 in
  non-Latin scripts, 8 emoji-heavy), the surface was recorded 0 times.
- The text report lists each decoded payload under its page URL, cut to 200
  characters and with control characters escaped; `--json` carries the same
  text in the surface's `content`.
- Scoring follows the existing rules: a site carrying the surface loses 3
  points for the surface type plus 4 per surface (stealth score 8), so its
  Wild Resilience Score, rating and exit code can change. Pages without a
  decoded payload score as before.
