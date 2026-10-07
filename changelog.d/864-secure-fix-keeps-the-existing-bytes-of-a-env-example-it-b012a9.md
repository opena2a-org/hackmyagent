---
type: fixed
issue: 864
---
`secure --fix` keeps the existing bytes of a `.env.example` it adds names to. The file was decoded as UTF-8 and written back, so bytes that are not valid UTF-8 (a Latin-1 `é` in a comment) were replaced with U+FFFD on lines the fix did not add. The fix now writes the original bytes followed by the missing names.
