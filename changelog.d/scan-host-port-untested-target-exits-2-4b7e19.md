---
type: fixed
---
- `scan` no longer exits 0 on a target it did not test. `scan 127.0.0.1:PORT`
  scans that port; when the port accepted the connection and then answered
  no HTTP request, the report said `Score: 100/100` and "No security issues
  found!". That port is now named by a new `SCAN-NO-ANSWER` finding (MEDIUM,
  score N/A when no open port answered), and the result's `unansweredPorts`
  lists it. A target that did not resolve or answer (`SCAN-UNREACHABLE`), a
  target with no open port among those scanned (`SCAN-NO-OPEN-PORTS`), and an
  open port that answered nothing all exit 2, the code of a run that reached
  no verdict, in the text and `--json` channels alike. A port that did answer
  is still scored and its findings keep exit 1 for critical or high.
