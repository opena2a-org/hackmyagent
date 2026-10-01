---
type: fixed
issue: 282
---
#### `secure --fix` keeps a hand-written `.env.example` (#282)

- **The CRED-001 fix no longer replaces an existing `.env.example`.** It built the file from
  scratch and wrote it over whatever was there, so a template holding
  `STRIPE_SECRET_KEY=`, `DATABASE_URL=postgres://localhost/db` and a comment came back as
  `# Environment variables` plus the one name the run generated, and nothing in the output
  said the file had been rewritten. The fix now keeps the file's bytes and appends only the
  names it does not already declare (`NAME=` or `export NAME=`), in the file's own line
  ending; a file that already declares every name is left byte-identical, and with no file
  present it is created as before. `rollback` restores the original. Tests:
  `__tests__/hardening/env-example-merge.test.ts` (three cases fail on the previous code).
