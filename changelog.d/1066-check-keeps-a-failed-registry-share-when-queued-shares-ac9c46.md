---
type: fixed
issue: 1066
---
#### `check` keeps a failed registry share when queued shares fail again on the same run (#1066)

- With contribution switched on, `check` sends the shares queued in
  `hma-pending-scans.json` and then the new scan's share. The two ran at the
  same time, and the retry wrote back the queued shares that failed again
  over the queue the new failed share had just been added to. With two
  queued shares and a registry answering 503, `check` of a git URL left the
  queue holding only the two queued shares, and the new scan's share was lost.
- `check` now finishes the retry before it sends the new share, so the queue
  keeps the queued shares that failed and the new one, and the queued shares
  are sent first.
