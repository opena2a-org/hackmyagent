---
type: fixed
issue: 497
---
#### Credential findings cite the line of the key they report (#497)

- `AST-CRED-001` found its line by searching the file again for the first
  credential-shaped string, so a SHA-256 digest or a `PEM_HEADER` string
  constant above the real key took the citation, and an AWS secret access key
  containing `/` produced no `AST-CRED-001` or `AST-CRED-003` finding at all.
  Both findings now cite the leftmost key the credential scan matched, with a
  `Verify:` command for that line.
- The PEM private key shape now matches the whole block and needs key material
  in the body, so an armor header on its own, or around `...`, is no longer
  reported as a private key. A block is skipped as a placeholder only when its
  body is nothing but placeholder words, so a real key whose base64 happens to
  spell `fake` or `dummy` is still reported.
