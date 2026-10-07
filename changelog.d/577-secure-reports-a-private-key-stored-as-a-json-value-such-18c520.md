---
type: fixed
issue: 577
---
#### `secure` reports a private key stored as a JSON value, such as the `secretKey` in `.opena2a/aim/identity.json` (#577)

- A private key written as a field value inside a JSON file was not seen by
  any check. A tree whose only sensitive file was `.opena2a/aim/identity.json`,
  holding the base64 Ed25519 `secretKey` that `fix-all --with-aim` used to
  write there, scored 98/100 with no credential or key finding and exited 0.
  CRED-002 (Private Key Files) now reports that file as CRITICAL and names the
  field, as in `.opena2a/aim/identity.json (secretKey field)`, and the missing
  `.gitignore` finding (GIT-001) rises from LOW to HIGH because a key is
  present. On that tree `secure` now scores 69/100 and exits 1.
- A JSON file counts when a field named `privateKey` or `secretKey`, in any
  case and with or without `_` or `-`, holds exactly 32 or 64 bytes written as
  base64 or hex. Placeholder values and public keys are not reported. A PEM
  private-key block inside a JSON file is unchanged by this fix.
