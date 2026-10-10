---
type: fixed
issue: 467
breaking: true
---
#### Breaking: UNICODE-STEGO-002 reads a codepoint range bound by its value, so a decoder written in decimal is detected like its hex twin (#467)

- `secure` reported a GlassWorm decoder only when it spelled the variation
  selector or tag range in hex (`cp >= 0xE0100`). The same decoder written
  `cp >= 917760 && cp <= 917999` was not reported at all. A range bound now
  counts by its value, in hex, decimal, `0o` or `0b`, with or without numeric
  separators, when it lies in U+FE00-FE0F or U+E0100-E01EF. A hex bound counts
  anywhere, as before. Any other spelling counts only as an operand of a
  comparison (`<`, `<=`, `>`, `>=`, `==`, `===`, `!=`, `!==`), so a decimal
  range table such as `[65024, 65039, 0]` is still not reported.
- The `codePointAt()` requirement, the two corroborators and both severities
  are unchanged, so a decimal decoder gets the severity its hex twin gets:
  CRITICAL with an `eval(` or `Function(` call or a variation-selector or
  tag-character payload in the same file, MEDIUM without. A decimal decoder
  carrying a variation-selector payload, which was reported only by
  UNICODE-STEGO-001, is now also reported by UNICODE-STEGO-002 at CRITICAL.
