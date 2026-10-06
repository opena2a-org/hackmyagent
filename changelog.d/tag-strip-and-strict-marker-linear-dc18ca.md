---
type: fixed
---
#### `wild` page text extraction and the `scan-soul` profile marker no longer slow down on unclosed openers

- A page that repeated `<` with no `>` made `wild` rescan to the end of the
  page from every `<` while it extracted the page's visible text: about 1.6
  seconds for 64 KiB, and roughly 400 seconds extrapolated to 1 MiB. A
  SOUL.md that repeated `<!--soul:profile=x` with no whitespace made
  `scan-soul` rescan the marker value from every `<!--`: 37 seconds for 1 MiB.
  Both now take a few milliseconds on 1 MiB. The extracted text and the
  profile read from a `<!-- soul:profile=NAME -->` marker are unchanged,
  including a valid marker that follows an unclosed one.
