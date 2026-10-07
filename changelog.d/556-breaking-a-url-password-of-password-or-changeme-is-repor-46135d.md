---
type: changed
issue: 556
breaking: true
---
#### Breaking: a URL password of `password` or `changeme` is reported at low, and `REDACTED` is not reported (#556)

- `secure` reported `postgres://registryadmin:password@db.example.com:5432/app`
  in a `config.yaml` as a high "Password embedded in URL" (SEM-CRED-001). That
  finding capped the score and made the run exit 1. A URL password that is
  exactly `password` or `changeme`, in any letter case, is now a low
  "Placeholder or default password in URL", with the fix "Replace it with a
  reference such as ${DB_PASSWORD} before deploying." It costs 3 points, does
  not cap the score, and does not on its own make the run exit 1.
- A URL password of `REDACTED` is now treated as a mask, like a run of `x`
  characters, and is not reported.
- Only the whole value matches. `password-8f3Kq`, `changeme-prod` and
  `xREDACTEDx` are still reported at the file's severity, and so are
  `default`, `none`, `null`, `true` and numeric passwords.
