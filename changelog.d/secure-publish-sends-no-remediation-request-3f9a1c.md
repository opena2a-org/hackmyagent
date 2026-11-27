---
type: changed
---
#### secure --publish sends no request to the remediation paths

- secure --publish sends the scan-token request and the publish, and no request to /api/v1/remediation/track or /api/v1/remediation/remediated. Its output and exit code are unchanged.
