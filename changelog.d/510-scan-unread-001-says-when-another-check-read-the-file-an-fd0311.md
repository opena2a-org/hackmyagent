---
type: fixed
issue: 510
---
#### SCAN-UNREAD-001 says when another check read the file, and gives a re-run instead of `chmod` for a file that is readable now (#510)

- A file one check read and another reader could not was reported by
  `secure` and `check` as one whose contents never reached a check, with
  `chmod u+r <file>` as the fix even when the file was readable. The finding
  now says how many checks read it and which reader could not: another check,
  or a reader outside any single check. When the file is readable at report
  time, the fix is the re-run of the same `secure` or `check` command; when
  it is not, the `chmod` fix stays and the finding says it is not readable
  now. A directory one check listed and another could not is reported the
  same way. The path is still counted as an unread input.
