---
type: fixed
issue: 444
---
`attack` settles an unconnectable target with its one liveness request (#444). The known issue noted under 0.27.0 used `http://127.0.0.1:9/x` as its reproduction; port 9 is a port the Fetch standard blocks, so `fetch` refused every payload before opening a socket and the run took ~112 s to reach `NOT MEASURED`. The probe now reads that refusal as definitive and names it, and treats `EHOSTUNREACH` and `ENETUNREACH` like `ECONNREFUSED` and `ENOTFOUND`; a reset or a timeout on the probe still runs the suite, so a live endpoint that drops the probe is measured. `attack --delay 0` now means no delay; it was read as unset and slept a second per payload.
