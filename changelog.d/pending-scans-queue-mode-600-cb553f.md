---
type: fixed
---
#### The pending-scans queue file is readable by its owner only
- `check` now writes `~/.opena2a/hma-pending-scans.json`, the queue of
  registry publishes waiting to be sent again, with mode 600 (owner read and
  write only), and narrows a queue file left at 644 to 600 the next time it
  writes it. It was written with no mode, which gives 644 under a umask
  of 022.
