---
type: fixed
---
#### `wild` no longer stalls on repeated injection phrases or an unclosed sitemap `<loc>`

- `wild` checks each HTML comment, `aria-label` and image alt text on a page
  for phrases such as "ignore all previous instructions". Text that repeated
  the first words of one of those phrases without finishing it slowed the
  check with the cube of its length: a comment holding 16 KiB of `ignore all `
  took more than 5 seconds. The check now takes a few milliseconds on 1 MiB,
  and it reports the same comments, labels and alt texts as before.
- A `sitemap.xml` that repeated `<loc>` with no `</loc>` on the same line took
  52 seconds per MiB while `wild` read its list of attack pages. It now takes
  about 2 milliseconds, and the list of pages is unchanged.
