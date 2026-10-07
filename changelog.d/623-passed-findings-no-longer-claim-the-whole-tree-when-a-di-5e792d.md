---
type: fixed
issue: 623
---
#### Passed findings no longer claim the whole tree when a directory could not be listed (#623)

- When `secure` could not list a directory, a passed record that names no
  file, such as CRED-002's "No private key files found in project directory",
  could still claim the whole tree in `--json` `allFindings`, right next to
  `coverage.unreadableInputs.directories: 1` and the SCAN-UNREAD-001 finding.
  Whether the caveat appeared depended on which walker recorded the directory
  first: a directory recorded after a check had already run, such as one under
  `src/node_modules/`, left that check's message unchanged.
- Every passed record that names no file now ends with "(a directory could
  not be listed — see SCAN-UNREAD-001)" whenever the scan recorded such a
  directory, however late. Only the message changes: verdicts, severities,
  the score and the exit code are the same as before.
