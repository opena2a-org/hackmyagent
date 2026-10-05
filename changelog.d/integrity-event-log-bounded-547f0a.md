---
type: fixed
---
#### The NanoMind integrity event log is rotated at 1 MiB and is no longer re-read in full on every run

- Every command start and every NanoMind scan appends a line to
  `~/.nanomind/integrity-events.jsonl`. The file grew without limit, and
  each append read and parsed the whole file, so a long-lived log of tens of
  megabytes added over 100 ms to each command. An append now reads only the
  end of the file. At 1 MiB the log moves to `integrity-events.jsonl.1`,
  replacing the previous one, and a new log starts, so after the first
  rotation the two files together stay under about 2 MiB. A log already
  larger than 2 MiB is removed on the first run after the upgrade instead of
  being kept; one between 1 MiB and 2 MiB is kept as the rotated segment, so
  the two files can total up to 3 MiB until the next rotation.
- Because an append now reads only the last line, a damaged line earlier in
  the log no longer stops the NanoMind layer: before, every command printed
  `hackmyagent: integrity check skipped (...)` and `secure` left out the
  NanoMind findings until the log was removed. A rotation that fails, for
  example because `integrity-events.jsonl.1` is a directory, leaves the log
  in place and appends to it rather than skipping the integrity check.
- The log is a hash-linked diagnostic record. Its hashes are not keyed and
  nothing checks it at startup, so the source no longer describes it as
  tamper-evident.
