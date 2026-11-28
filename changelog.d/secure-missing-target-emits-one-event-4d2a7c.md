---
type: fixed
---
#### secure on a target that does not exist emits one usage event

- `secure <directory>` on a path that does not exist ended before the
  telemetry hook ran, so the run emitted no event. It now emits exactly one
  event, like the empty-directory case. The exit code is unchanged.
