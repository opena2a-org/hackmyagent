---
type: changed
issue: 951,756
breaking: true
---
#### A benchmark over a scan that read no file is `Not Assessed` (#756)

- `secure -b oasb-1` on a target from which no file was read now prints
  `Rating: Not Assessed` and
  `Compliance: not measured (no file was read from <target>)`, and exits 2
  (not measured). This holds for any such target, not only an empty
  directory: a directory holding nothing but a `.git` directory reads the
  same. On 0.33.2 both printed `Rating: Not Passing` and
  `Compliance: 43% (3/7 verified controls)` and exited 1.
- `--fail-below` is not evaluated over the withheld compliance: the run
  prints `--fail-below <n> not evaluated: no compliance was measured` and
  exits 2, where 0.33.2 compared 43% with the threshold.
- `secure -b oasb-2` on such a target prints
  `Infrastructure Score (OASB-1): not measured`, computes no composite score,
  and exits 2, where 0.33.2 printed `Infrastructure Score (OASB-1): 43%` and
  `Composite Score: 22/100` and exited 1.
- `hackmyagent secure <target> --json | jq .coverage.filesExamined` prints `0`
  for such a target. Run the benchmark on the project root that holds the
  files OASB-1 examines (package manifest, agent or MCP config, source) to get
  a rating.
