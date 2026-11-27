---
type: fixed
---
- The `Fix:` line of UNICODE-STEGO-004 (Invisible Plane-14 Characters
  Detected) was `xxd <file> | grep "f3a0"`. xxd prints bytes in pairs, so a
  character starting at an odd byte offset showed as `f3 a0` split across two
  groups and the command printed nothing for it. It is now a raw-byte search,
  `LC_ALL=C grep -nbo "$(printf '\363\240[\200-\207][\200-\277]')" <file>`,
  which prints one row with the line and byte offset for every character in
  U+E0000-U+E01FF wherever it starts, and the line says what to do with each:
  delete it, or write it as an escape sequence such as `\u{E0041}` where a
  string literal needs it.
