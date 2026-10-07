---
type: fixed
issue: 543
breaking: true
---
#### secure reports a Hugging Face or GitLab token that has no credential word near it (#543)

- `secure` scored a file holding a bare `hf_` token (34 or more characters) or
  `glpat-` token 98/100 and exited 0, unless a word such as `token` or `secret`
  sat within 100 bytes of the value. Both shapes now raise AST-CRED-001 (high)
  and AST-CRED-003 (critical), the findings an AWS access key raises, and the
  scan exits 1. The finding names the token type and prints `[REDACTED]` in
  place of the value.
- A `glpat-` value is reported only when its body mixes upper- and lower-case
  letters, so runner slugs such as `glpat-shared-linux-docker-runner-1` and
  one-letter placeholders stay quiet. `hf_hub_download` and other
  `huggingface_hub` names are not reported.
- The signal added is the vendor prefix. Key-name assignments such as
  `DB_PASSWORD = "..."` and passwords inside connection strings (#538) are
  still not detected, so a clean result is not yet evidence that no credential
  is present.
