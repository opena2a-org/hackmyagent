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
- A header is now not reported when an END marker begins within 4096
  characters after it and fewer than 40 base64 characters lie between: no
  key body fits in that. A real key, a key cut off after its first body
  line, and a header with no END marker in reach are still reported.
