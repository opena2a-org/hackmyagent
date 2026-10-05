---
type: fixed
---
#### Scans no longer wait 3 seconds for a NanoMind daemon that is not installed

- `secure`, `check` on a local directory, and the other commands that run the
  NanoMind semantic pass try to start the local NanoMind daemon when none is
  running. When the daemon command was not installed, the failed start was
  still treated as a launch, and every scan polled for the daemon for the full
  3-second startup window before going on without it. Measured with `secure`
  on the kitchen-sink corpus fixture with no daemon installed: 3.5s before,
  0.4s now, with the same findings, score, verdict and exit code. A daemon
  that does launch is still waited for, as before.
