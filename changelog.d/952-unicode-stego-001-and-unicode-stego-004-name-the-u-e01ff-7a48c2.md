---
type: fixed
issue: 952
---
#### UNICODE-STEGO-001 and UNICODE-STEGO-004 name the U+E01FF end of the range they report (#952)

- `secure` reported a raw U+E01F0 to U+E01FF in a source file as
  UNICODE-STEGO-001 with the message "Found tag characters (U+E0100-E01EF)",
  a range that does not contain the character it found. The message now reads
  "tag characters (U+E0100-E01FF)", and the UNICODE-STEGO-004 description and
  guidance name U+E0000-U+E01FF. Which characters each check reports, and at
  what severity, is unchanged.
