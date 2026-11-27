---
type: fixed
---
- `secure` no longer reports AST-CRED-003 (Hardcoded Secret Detected) on a
  keyword argument that passes a variable of the same name, such as
  `tokenizer_provenance=tokenizer_provenance,` in a Python call. The
  high-entropy fallback read `name=name` as one 40+ character value. Only a
  value identical to its name is skipped: an unquoted literal such as
  `DB_PASSWORD=<long value>` in a config file is still flagged.
