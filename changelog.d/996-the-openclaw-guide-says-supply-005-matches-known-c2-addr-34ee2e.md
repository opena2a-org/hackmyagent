---
type: fixed
issue: 996
---
#### The OpenClaw guide says SUPPLY-005 matches known C2 addresses in skill files, not that it checks outbound connections (#996)

- The ClawHavoc section of the OpenClaw use-case guide listed "Outbound
  connections to known C2 domains" among the indicators checked. `SUPPLY-005`
  searches skill file content for known ClawHavoc command-and-control IP
  addresses and observes no network connection. The guide now says it is a
  text match on file content, and to check network logs for connections to
  any address it reports.
