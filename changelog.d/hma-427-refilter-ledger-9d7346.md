---
type: fixed
issue: 427
---
A finding the semantic merge reintroduces and the CLI's post-merge re-filter drops is now held to the `coverage.suppressedFailures` ledger by a regression test (#427). The re-filter moved from `cli.ts` to `src/hardening/semantic-refilter.ts` so the test drives it in-process; its behaviour is unchanged.
