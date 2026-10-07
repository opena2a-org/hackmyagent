---
type: fixed
issue: 394
---
#### SARIF `$schema` points at a schema that exists (#394)

- **Every SARIF document named a `$schema` URL that returns 404.** The three writers
  (`secure -f sarif`, the benchmark SARIF and `attack -f sarif`) each carried
  `raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`,
  which the upstream repository moved off `master`. They now share one constant, the
  schema's own `id` (the schema is JSON Schema draft-04):
  `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`.
  The document content is unchanged; only the pointer an editor or validator resolves.
