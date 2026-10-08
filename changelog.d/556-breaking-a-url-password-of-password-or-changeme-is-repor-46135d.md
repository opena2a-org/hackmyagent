---
type: changed
issue: 556
breaking: true
---
#### Breaking: a URL password of `password` or `changeme` is reported at low, and `REDACTED` is not reported (#556)

- `secure` reported `postgres://registryadmin:<password>@db.example.com:5432/app`
  in a `config.yaml`, with the password `password`, as a high "Password
  embedded in URL" (SEM-CRED-001). That finding capped the score and made the
  run exit 1. A URL password that is exactly `password` or `changeme`, in any
  letter case, on a local or placeholder host is now a low "Placeholder or
  default password in URL", with the fix "Replace it with a reference such as
  ${DB_PASSWORD} before deploying." It costs at most 2 points, does not cap
  the score, and does not on its own make the run exit 1.
- A local or placeholder host is loopback (`localhost` or `127.0.0.0/8`), a
  reserved name (`example.com`, `example.net`, `example.org` and their
  subdomains, or a name under `.example`, `.test`, `.invalid`, `.localhost` or
  `.local`), or a single-label service name such as `db`. On any other host,
  such as `postgres://admin:<password>@prod-db.acme.io/app` with the password
  `password`, the password keeps the file's severity, because a guessable
  password on a deployed host is credential exposure.
- A URL password of `REDACTED` is now treated as a mask, like a run of `x`
  characters, and is not reported.
- Only the whole value matches. `password-8f3Kq`, `changeme-prod` and
  `xREDACTEDx` are still reported at the file's severity, and so are
  `default`, `none`, `null`, `true` and numeric passwords.
