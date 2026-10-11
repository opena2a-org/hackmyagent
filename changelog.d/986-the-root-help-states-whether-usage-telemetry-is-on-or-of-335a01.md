---
type: fixed
issue: 986
---
#### The root help states whether usage telemetry is on or off (#986)

- `hackmyagent --help` said "Usage telemetry is on" even when it was off, for
  example under `OPENA2A_TELEMETRY=off`, or under CI or a test runner without
  `OPENA2A_TELEMETRY=on`. It now states the same on/off state that
  `hackmyagent --version` prints on its `Telemetry:` line.
