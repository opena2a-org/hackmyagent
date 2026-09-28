---
type: fixed
issue: 527
---
#### `docs/REGISTRY_INTEGRATION.md` examples run against the shipped CLI

- **The registry reporting examples are corrected (#527).** `attack` takes its target
  as a positional argument (the doc passed `--target`, an unknown option), `--intensity`
  takes `passive`, `active` or `aggressive` (the doc used `high` and `medium`), and `secure`
  scans a local directory (the doc passed an npm package name). The attack examples no
  longer use `--local` with `--registry-report`: a `--local` run tests no agent and is
  never reported. The parameters table and the missing-key error now match the CLI:
  `--registry-url` defaults to `https://api.oa2a.org`, and `--registry-key` is required
  only with `--version-id`.
- **The flag-citation walker reads commands continued with a trailing `\`.** It read
  markdown one physical line at a time, so every flag after the first line of a
  multi-line example went unchecked; that is how `attack --target` survived.
