---
type: fixed
issue: 959
---
#### UNICODE-STEGO-003 and UNICODE-STEGO-002 read U+E01F0-E01FF like the rest of the range UNICODE-STEGO-001 reports (#959)

- UNICODE-STEGO-003 counted U+E01F0-E01FF as visible characters, so an `eval("...")` whose string held 30 copies of U+E01F0 or U+E01FF was not reported, while the same string of U+E01EF was. It now skips U+E0000-E01FF, the range UNICODE-STEGO-004 reports, when it counts visible characters, and reports all three.
- UNICODE-STEGO-002 counted a range literal only up to 0xE01EF, so a decoder bounded at `cp <= 0xE01FF`, the end of the range UNICODE-STEGO-001 reports, did not hold one. A literal in 0xE01F0-0xE01FF now counts the same as one in 0xE0100-0xE01EF, measured with hex, decimal and octal spellings.
- Both ranges only gain code points and no severity changes.
- Not changed in this release: the NanoMind stego analyzer still ends its tag-character range at U+E01EF.
