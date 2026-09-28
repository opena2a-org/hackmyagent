---
type: changed
issue: 520
---
#### The `--nanomind` coverage sweep no longer re-reads compiled files through the coverage ledger (#520)

- Each coverage-sweep candidate now states its provenance. A `compiled`
  candidate was already read by the compile loop, so the sweep re-reads it
  through the bridge's off-ledger re-read (the one citation lines already use)
  and skips it if that fails. Before, the sweep re-read it through the tracked
  namespace outside any check's frame, so a file that became unreadable between
  the two reads recorded an unread input no later read could clear: exit 2 and
  a `chmod` remedy naming a file the run had read. Requires `--nanomind` and a
  running analyst daemon.
- `sweep-only` documents (`.html`, `.txt`, `.github/`, `.well-known/`) keep
  their tracked read, which is their first read.
