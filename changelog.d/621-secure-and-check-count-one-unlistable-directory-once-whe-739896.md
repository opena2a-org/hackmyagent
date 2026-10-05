---
type: fixed
issue: 621
---
#### secure and check count one unlistable directory once when it is reachable under two path spellings (#621)

- On a case-insensitive filesystem (the macOS default), a directory the scan
  could not list was recorded twice when its name on disk differed in case from
  a name a check probes, such as `Src` against `src`. `secure --json` reported
  `coverage.unreadableInputs` as `{"count":2,"codes":{"EACCES":2},"directories":2}`
  with two `SCAN-UNREAD-001` findings (`src/` and `Src/`), and the score
  deduction was applied twice, although one `chmod u+rx Src` cleared both.
- `secure` and `check` now report that directory once, and the finding names it
  as the filesystem does (`Src/`). A probe beneath the other spelling is
  attributed to the same directory. A directory or file that failed both under
  its own name and through a symbolic link to it is also one record.
- Two different directories are still two records, a single record keeps the
  path it was recorded under, and the exit code for a scan that could not
  examine everything is unchanged.
