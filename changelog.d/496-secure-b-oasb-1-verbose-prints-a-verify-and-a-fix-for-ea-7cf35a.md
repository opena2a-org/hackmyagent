---
type: fixed
issue: 496
---
#### `secure -b oasb-1 --verbose` prints a Verify and a Fix for each failed control (#496)

- Under `--verbose`, a failed OASB-1 control listed its evidence lines and
  nothing else: no command to confirm a finding and no remediation, while the
  plain `secure --verbose` printed both for the same records. Each evidence
  line is now followed by a `Verify:` line. When the record carries a line,
  it is the plain scan's command, `sed -n '<line>p' <file>` with the file
  joined onto the scanned directory. When the record carries no line, it reads
  `Verify: not available (the record carries no line)`. After the evidence
  lines the control's remediation is printed through the plain scan's fix
  renderer: `→  <command>` for a command, `Fix: <text>` for guidance. A record
  that has no line yet, such as SEM-PERM-002 on `.claude/settings.json`, gets
  the `not available` line until its check records one. The same lines appear
  in the OASB-1 part of `secure -b oasb-2 --verbose`. Output without
  `--verbose` and the `--format json` report are unchanged.
