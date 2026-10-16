---
type: fixed
---
#### Deep analysis keeps its cache and daily budget in the scanned tree's state directory and redacts what it stores

- `secure --deep` and `secure --scan-depth deep` keep the deep analysis cache
  and its daily budget record in the state directory of the scanned tree,
  `~/.opena2a/projects/<key>/llm-cache/` (under `$OPENA2A_HOME` when it is
  set), one directory per scanned tree, readable by the user only. Deep
  analysis writes nothing inside the scanned tree and no `.hackmyagent-cache/`
  directory in the working directory, two scanned trees never share a cache
  entry, and the daily budget (`HACKMYAGENT_LLM_BUDGET`) is counted per
  scanned tree.
- Every finding text the cache stores passes through the same credential
  redaction as the behavioural simulation, so a finding that quotes a
  credential-keyed value, such as `db_password: <value>`, is stored with the
  value replaced by `[REDACTED]`. The redaction does not recognise every
  credential: a value quoted with nothing that marks it as one is stored as
  written.
- When the state directory would sit inside the scanned tree, as in a scan of
  the home directory with the default `~/.opena2a`, deep analysis keeps no
  cache and no budget record between runs, so `HACKMYAGENT_LLM_BUDGET` limits
  each run of that scan rather than each day.
- A `.hackmyagent-cache/` directory in a project is no longer read or written
  by deep analysis and can be deleted, for example with
  `rm -rf .hackmyagent-cache` in the directory that holds it.
