---
type: changed
issue: 963
---
#### Usage telemetry is off under CI and test runners unless `OPENA2A_TELEMETRY=on` is set (#963)

- A run with a CI variable (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI` or another CI
  service's marker) or a test-runner variable (`VITEST`, `JEST_WORKER_ID`,
  `NODE_TEST_CONTEXT`, `NODE_ENV=test`) sent a usage event like an interactive
  run. Such a run now sends no usage event, and `hackmyagent --version`
  prints `Telemetry: off`. `OPENA2A_TELEMETRY=on` turns usage telemetry back on
  for one run; a persisted `hackmyagent telemetry off` still keeps it off.
  `hackmyagent --help` states the rule under `Telemetry:`.
