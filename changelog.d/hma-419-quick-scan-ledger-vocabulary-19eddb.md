---
type: fixed
issue: 419
---
#### The quick-scan scope sentence names categories the way the coverage ledger does (#419)

- **One vocabulary for the categories a quick scan did not evaluate.** A `check` quick scan's
  scope sentence and follow-up line said the run did not evaluate `credentials, git hygiene,
  MCP config, file permissions`, while the Categories line and `--json`'s
  `coverage.categories` name the same categories `MCP` and `sandbox` (the `PERM` checks roll
  up under `sandbox`). A reader told the scan "did NOT evaluate file permissions" then found
  `sandbox: not-examined` with nothing connecting the two. The sentence now uses the ledger's
  labels: `credentials, git hygiene, MCP, sandbox`. The test that pinned the old translation
  table went out with #740; `__tests__/ui/quick-scan-labels.test.ts` now asserts each entry is
  a ledger category, through a new `isCoverageCategory` export.
