---
type: fixed
issue: 539
---
#### fix-all no longer reports an empty or variable-reference `.env` value as a hardcoded credential (#539)

- `fix-all` reported `CRED-001` HIGH "Hardcoded credential" for any `.env` or
  `.env.local` line whose key name looked like a credential, without reading
  the value. `API_KEY=` and `API_KEY=${OPENAI_API_KEY}` were both reported.
- The rule now reads the value. An empty value and a value that only names
  another variable (`${NAME}` or `$NAME`) are not reported. A literal value
  under a credential key name is still reported HIGH, as before.
