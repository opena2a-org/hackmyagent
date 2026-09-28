---
type: fixed
issue: 615
---
`secure -b oasb-1` no longer reports every unverified control as needing manual or forward verification (#615). The `Unverified:` line now splits the count by the reason each `[?]` row prints, for example `Unverified: 44 controls (21 require manual/forward verification, 23 automated with no scanner data)`, and the `--verbose` legend names both reasons. A category in which no control was measured now carries `"compliance": null` on `--format json` and `--format asp` (it read `0` beside `"passed": 0, "failed": 0`), the same zero-denominator rule the level figures follow since #458, and the HTML report shows it as `n/a` with the unverified icon instead of a green check over a red 0% bar. `BenchmarkCategoryResult.compliance` is typed `number | null` accordingly.
