---
type: fixed
---
#### Help no longer calls usage telemetry anonymous

- `hackmyagent --help` said "Anonymous usage telemetry is on", and the
  `telemetry` subcommand was described as toggling "anonymous usage
  telemetry". Every usage event carries a persistent install ID, the one
  `hackmyagent telemetry status` prints, so the help now says that instead:
  "Usage telemetry is on and each event carries a persistent install ID.
  Disable: OPENA2A_TELEMETRY=off". The `telemetry` description reads
  "Inspect or toggle usage telemetry: on | off | status". What is sent and
  how to turn it off are unchanged.
