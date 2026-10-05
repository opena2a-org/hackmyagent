---
type: fixed
---
#### Overlapping scans on one `HardeningScanner` instance each report their own results

- A program that called `scan()` twice on the same `HardeningScanner`
  instance without waiting for the first call saw each result carry the
  state of whichever scan started last: the first result listed the other
  tree's withheld links, and its retarget commands named the other call's
  CLI. Each call now keeps its own coverage ledger, CLI name and fix
  bookkeeping, so an overlapping scan reports exactly what it reports when
  it runs alone. One scan at a time, and the `hackmyagent` commands, behave
  as before.
