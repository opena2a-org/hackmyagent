---
type: fixed
---
#### Report redaction covers every key length the detector reports

- The redaction applied to report text, the declared purpose included, now
  removes an `sk-` key with a body of 32 characters or more, the lengths the
  detector reports for that shape. Every other vendor shape was already
  removed at the lengths the detector reports it.
- `secure` decides whether a file is a test, an example or documentation
  partly from its declared purpose. That decision now reads the purpose with
  every credential-shaped value removed, a placeholder containing EXAMPLE
  included, so a placeholder on the first line does not decide the result for
  a real key further down. A key containing EXAMPLE is still a placeholder and
  produces no finding.
