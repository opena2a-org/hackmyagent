---
type: fixed
---
#### `check` sends a queued registry share with the findings it was queued with
- When `check` could not share a scan with the registry, it queued a finding
  count. The next run that shared sent the queued scan with an empty findings
  list, that run's time as the scan time and its own version as the tool
  version. The registry reads an empty findings list as a scan with no
  findings, so a failing scan shared on a retry was recorded as one with
  none. The queue now holds the submission the failed share sent, and a
  retry sends its findings, scan time and tool version unchanged.
- A queued scan that an earlier version saved without its findings is
  removed from the queue and not sent, and `check` prints one line saying
  how many. A new `check` of the same target shares a new scan.
