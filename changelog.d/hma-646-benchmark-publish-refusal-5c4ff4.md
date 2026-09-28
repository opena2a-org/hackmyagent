---
type: fixed
issue: 646
---
#### `secure -b` refuses the publish and contribute flags instead of dropping them (#646)

- **`--publish`, `--ci-publish`, `--registry-report`, `--version-id` and `--contribute` exit 1
  with `-b oasb-1` or `-b oasb-2`.** Both benchmark arms return before the publish and
  contribute steps run, so these flags were accepted and dropped: no attempt, no `publish` key
  in `--format json`, nothing on stderr. The refusal names every dropped flag and is raised
  before any scan runs, at the same site as the `-b` format refusal. `--no-contribute` stays
  allowed. The five option descriptions in `secure --help` now say `not with -b`.
