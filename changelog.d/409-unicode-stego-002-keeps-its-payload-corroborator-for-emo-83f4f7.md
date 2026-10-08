---
type: fixed
issue: 409
---
#### UNICODE-STEGO-002 keeps its payload corroborator for emoji selectors, and U+FE0E after a digit is still reported (#409)

- `secure` no longer downgrades a `GlassWorm Decoder Pattern Detected` finding
  from CRITICAL to MEDIUM when the only payload in the file is a presentation
  selector (U+FE0E or U+FE0F) after an emoji such as U+2B50 (star). The emoji
  itself is still not reported by UNICODE-STEGO-001, but a decoder in the same
  file can read the selector after each emoji as a bit, so the selector keeps
  corroborating UNICODE-STEGO-002 as it did before.
- A text presentation selector (U+FE0E) directly after a digit, `#` or `*` is
  reported again as a CRITICAL variation-selector finding by UNICODE-STEGO-001.
  Only U+FE0F builds a keycap; the exemption for U+FE0E applies after an emoji
  only.
- In a file whose zero-width joiner only builds an emoji such as U+1F9D1 U+200D
  U+1F680 (astronaut), tag characters in U+E0000-E00FF elsewhere in the file are
  now reported by UNICODE-STEGO-004 at their own line, where the exempted
  joiner's UNICODE-STEGO-001 finding used to stand in for them.
