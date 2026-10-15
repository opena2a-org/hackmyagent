---
type: fixed
---
- What the registry and the contribution endpoint receive now matches the run
  that sent it. Every payload is built from the run's own result in one place,
  and these fields were corrected (measured against a local capture registry
  before the change):
  - `scan-soul --publish` sent `findings: []`, `score: 100` and
    `verdict: "pass"` for a run that printed 3/100 and failed controls. It now
    sends every control the run evaluated at its own severity, the score the
    run printed and `verdict: "fail"` when the run's gate failed.
  - `scan-soul --contribute` counted every failed control as medium and sent
    `verdict: "pass"`. Each control is now counted at its own severity, and the
    verdict follows the run's gate.
  - `detect --contribute` sent `totalChecks: 0`, zero for every severity,
    `score: 0`, `verdict: "pass"` and `durationMs: 0` whatever the scan found.
    It now sends the findings the run printed counted by severity, the
    governance score it printed, the verdict those findings make and the time
    the scan took, with no check count, since `detect` counts findings.
  - `secure --ci-publish` and `check`'s share kept the query string and
    fragment of a repository URL (`.git?ref=main#readme`). Both are removed now.
  - `secure --publish`, `--ci-publish`, `--registry-report`, `--version-id`
    and `--contribute`, `scan-soul --publish` and `--contribute`,
    `attack --publish`, `--registry-report` and `--version-id`, `check`'s share
    and `detect --contribute` were stamped with the moment each payload was
    built, after the scan had ended (for `--ci-publish`, in its scan id). They
    now carry the scan's own time.
