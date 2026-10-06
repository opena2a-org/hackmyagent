---
type: fixed
---
#### `secure` no longer stalls on a line that repeats `curl` or `wget` without a pipe to a shell

- Nine patterns in `secure` look for `curl` or `wget` piped into `sh`,
  `bash` or `sudo`: the ClickFix patterns of SKILL-007, the npm script
  patterns of DEP-004, the two patterns of NEMO-001 and the pattern of
  INSTALL-001. From every `curl` or `wget` on a line, each one read to the end
  of the line (for INSTALL-001, to the next `|`) and backed off looking for
  the pipe, so a line that repeated the command without the pipe slowed it
  with the square of the line's length. One 256 KiB line of `curl ` took about
  5 seconds in each pattern, and a shell script holding a 512 KiB line of
  `curl ` and one of `curl | ` took 95 seconds in NEMO-001. Each now takes a
  few milliseconds per MiB, and the checks report the same findings and
  lines as before. The bracket strip MEM-006 applies to a `push` receiver now
  reads its input once too; the receiver pattern before it is unchanged.
