---
type: fixed
issue: 926
---
#### A `.hmaignore` check pattern with many `*` no longer stalls `secure` and `check` (#926)

- A `!<CHECK-ID>` or `<path>:<CHECK-ID>` pattern made of many `*` and a few
  letters, such as `!` followed by 24 `*` and `X`, made `secure` and `check`
  run for minutes, because each comparison of the pattern with a finding's
  check id took time that grew exponentially with the number of stars. Such a
  line now adds no measurable time to a scan, and every pattern matches the
  same check ids as before. Tools that call `matchHmaIgnore` get the same fix.
