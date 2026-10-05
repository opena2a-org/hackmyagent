---
type: fixed
issue: 542
---
#### A stalled model download no longer hangs `secure` (#542)

- When no NanoMind model was cached, `secure` downloaded it before writing its
  report, with no time limit. A connection that was accepted and then went
  silent kept the scan open until it was killed, with no output. A download
  that receives nothing for 10 seconds is now abandoned, the scan continues on
  vocabulary scoring, and the report is written as usual. A slow download that
  keeps receiving data still completes.
