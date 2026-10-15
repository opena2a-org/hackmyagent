---
type: fixed
issue: 1027
breaking: true
---
#### Breaking: `secure` reports credentials in README, CHANGELOG and package metadata files it used to skip (#1027)

- The semantic layer skipped every file whose name began with `readme`,
  `changelog`, `license`, `contributing`, `history` or `authors`, and
  `package.json`, `package-lock.json`, `tsconfig.json` and `.npmrc`, before
  any analyzer ran. A token in `CHANGELOG.md`, `README.md`, `src/history.ts`
  or `tsconfig.json` was not reported, and a `package.json` holding a GitHub
  token in `scripts`, scanned alone, scored 93/100 and exited 0.
- Source and config files whose names only begin with one of those words now
  take the route of their file type. A token in `src/history.ts`,
  `app/authors.py`, `data/licenses.json` or `ci/contributing.yml` is reported
  with the same check IDs as the same file under another name.
- `package.json` and `tsconfig.json` are now read by the credential analyzer,
  and still not by the capability, governance, scope or prompt analyzers. The
  `package.json` above now reports AST-CRED-003 (critical) at the token's
  line, scores 69/100 and exits 1.
- `README.md`, `CHANGELOG.md`, `LICENSE.md`, `CONTRIBUTING.md`, `HISTORY.md`
  and `AUTHORS.md` report a vendor-prefixed credential, such as a GitHub or
  Slack token, as AST-CRED-003 at its line. A placeholder is not reported: a
  body of one repeated character, the alphabet and digits in order, or a
  marker such as `FAKE`, `EXAMPLE`, `PLACEHOLDER` or `YOUR_`. These six
  documents get this narrower check because the full check reads ordinary
  changelog text as secrets: under other file names, 81 documentation files
  from 49 npm packages report 6 high AST-CRED-003 findings, for example on a
  git commit ID in a commit link, and under their own names they report none.
- Known gap: a credential with no vendor prefix, such as a 40-character hex
  value after `API_SECRET=`, is not reported in those six documents. The same
  line in another markdown file, such as `notes.md`, is reported as
  AST-CRED-003.
- `package-lock.json` is still not analyzed: under another name, an
  `integrity` value in it is reported as AST-CRED-003. Documents with no
  extension, such as `LICENSE`, and `.txt` files, such as `NOTES.txt`, are not
  read by the semantic layer, as before.
