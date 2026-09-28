---
type: fixed
issue: 493
---
#### AST-CRED-001's fix text no longer quotes a line the finding does not cite (#493)

- **The `CRED-EXPOSURE` fix sentence carries no quoted context.** It read `Credentials in this
  source_code ("<declaredPurpose>") are exposed in version control.`, and on a source file
  `declaredPurpose` is the first content line, which is usually not the line holding the
  credential. Measured on main before this change, on a `src/config.js` with a SHA-256 build
  digest on line 2 and an API key on line 5: the fix text quoted `const BUILD_SHA =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41..."`, a digest described as the credential's context.
  It now reads `Credentials in this source_code are exposed in version control.`; the finding's
  `file:line` and evidence locate the secret. Score, findings and severities are unchanged on
  that fixture (69/100 before and after). This also removes one of the places artifact text was
  interpolated into fix output. Regression: `__tests__/nanomind-core/cred-exposure-fix-citation.test.ts`,
  and `declared-purpose-pem-body.test.ts` now pins that this branch quotes no purpose.
