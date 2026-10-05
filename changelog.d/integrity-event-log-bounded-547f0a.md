---
type: fixed
---
#### The NanoMind integrity event log stays under about 2 MiB and is no longer re-read in full on every run

- Every command start and every NanoMind scan appends a line to
  `~/.nanomind/integrity-events.jsonl`. The file grew without limit, and
  each append read and parsed the whole file, so a long-lived log of tens of
  megabytes added over 100 ms to each command. An append now reads only the
  end of the file. At 1 MiB the log moves to `integrity-events.jsonl.1`,
  replacing the previous one, and a new log starts. A log already larger
  than 2 MiB is removed on the first run after the upgrade instead of being
  kept.
- The log is a hash-linked diagnostic record. Its hashes are not keyed and
  nothing checks it at startup, so the source no longer describes it as
  tamper-evident.
