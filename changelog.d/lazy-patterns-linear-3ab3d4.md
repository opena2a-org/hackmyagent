---
type: fixed
---
#### Seven patterns in `secure`, `scan-soul` and `wild` no longer rescan the input from every unclosed opener

- A scanned file or page that repeated an opener with no closer (`<!--`,
  `<span`, `<script`, `<style`, `soul:profile=` or `eval('`) made the matching
  pattern rescan to the end of the input from every opener: on 1 MiB of them
  each pattern took between 4 and more than 15 seconds. Each pattern now stops
  at the first opener with no closer and takes a few milliseconds on the same
  input. The findings and their content are unchanged: hidden HTML comments,
  invisible spans and JSON-LD instructions in `wild`, the attempted value of a
  malformed `soul:profile` marker in `scan-soul`, and hidden comment
  instructions (LIFECYCLE-007) and eval of an invisible string
  (UNICODE-STEGO-003) in `secure`.
