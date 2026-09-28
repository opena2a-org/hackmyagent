---
type: fixed
issue: 418
---
#### `-b oasb-1 --json` carries the verification procedure for each control the scan leaves open

- **An `unverified` control record now includes `audit`, the catalogue's numbered
  procedure for checking that control by hand (#418).** The field was populated on most
  OASB-1 controls and read by nothing: not the text report, not `--json`, not SARIF, not
  `explain`. It rides only on `unverified` records, because those are the controls the scan
  could not settle and a manual check is the next step; `passed`, `failed` and
  `not-applicable` records are unchanged. Verify:
  `hackmyagent secure <dir> -b oasb-1 --format json | jq '[.categories[].controls[] | select(.audit)] | length'`.
