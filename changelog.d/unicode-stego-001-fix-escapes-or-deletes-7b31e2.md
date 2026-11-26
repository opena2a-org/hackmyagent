---
type: fixed
---
- The `Fix:` line of UNICODE-STEGO-001 (Invisible Unicode Codepoints
  Detected) was `xxd <file> | grep …`, which only locates the bytes. It now
  names the change. A code point inside a string literal gets its escape
  sequence, for example "replace the raw U+200B ... with its escape sequence
  `\u200B`". Anywhere else (code, a comment) the line is a `perl -CSD -i -pe`
  command that deletes the invisible code points from the reported line.
