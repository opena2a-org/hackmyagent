---
type: fixed
issue: 872
---
#### Benchmark JSON and SARIF name the findings `.hmaignore` and `--ignore` withheld (#872)

- With an `.hmaignore` check rule such as `!MCP-001`, or `--ignore`, the
  withheld findings never reach the benchmark, so a control they measure can
  read `unverified` instead of failed or passed. `secure -b oasb-1 --json`
  carried no record of that, and `-b oasb-1 -f sarif` had no
  `runs[0].properties`. The benchmark JSON now carries the `suppressed`,
  `outOfScope` and `hmaignore` keys that `secure --json` uses, and the
  benchmark SARIF carries `suppressed` and `outOfScope` in
  `runs[0].properties`, as the plain `secure -f sarif` report does. Each
  row names the check, its severity and count, and the rule channel; no file
  content or evidence. Ratings, control statuses and exit codes are
  unchanged.
