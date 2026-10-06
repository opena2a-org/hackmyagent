---
type: fixed
---
#### `wild` no longer slows down on a page that repeats `<meta` or `<img` with no `>`

- A page that repeated `<meta ` or `<img ` with no `>` made `wild` rescan to
  the end of the page from every one of them while it looked for meta tags
  with AI instructions and for image alt text: 75 seconds for 1 MiB of
  `<meta ` and 92 seconds for 1 MiB of `<img `. A single meta tag that
  repeated its `name` attribute slowed down the same way. Each now takes a few
  milliseconds on 1 MiB. The meta tag and image alt surfaces `wild` reports
  are unchanged, including a value that contains `>` and a tag behind a
  second unclosed opener.
