---
type: fixed
breaking: true
---
#### A PEM private-key header around a placeholder is no longer reported as a private key

- `secure` reported AST-CRED-003 "PEM private key" for any
  private-key armor header, so a README, config template or log holding
  `-----BEGIN RSA PRIVATE KEY-----`, then `<your private key here>`, `...` or
  `[REDACTED]`, then the END line, was reported as a hardcoded private key
  and the run exited 1.
- A header and END pair is now not reported only when fewer than 40 base64
  characters lie between them and no base64 run of key-body length (40
  characters or more in a row, line breaks and escaped line breaks ignored)
  stands between the pair and the neighbouring private-key header, or the
  start or the end of the text, on either side. There is no fixed window. A
  real key, a key cut off after its first body line, a header with no END
  marker before the next header, and a key body placed before the pair, after
  it, after filler of any length, after a second END marker or behind an END
  marker in a comment are all still reported.
