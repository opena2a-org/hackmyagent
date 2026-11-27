---
type: fixed
---
#### Recording a scan or a contribution choice no longer fails on a non-object `contribute` or `telemetry` value in config.json

- When `~/.opena2a/config.json` (or `$OPENA2A_HOME/config.json`) held a string, number, boolean or array under `contribute` or `telemetry`, counting a scan or saving the `--contribute` choice threw a TypeError, or left the scan count unchanged when the value was an array. Such a value now reads as empty, like a file whose whole value is not an object: the scan count advances and the choice is saved, each written as an object in its place.
