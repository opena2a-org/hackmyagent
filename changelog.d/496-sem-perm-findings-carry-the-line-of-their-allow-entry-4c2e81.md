---
type: fixed
issue: 496
---
- SEM-PERM-002 (Unrestricted Bash access) and SEM-PERM-003 (Write access
  outside project scope) on `.claude/settings.json` now cite the line of the
  allow entry they are about, so the report prints `file:line` and a `Verify:`
  command for them. Each finding records the entry as written in the file,
  and the line is found in the file's own bytes. An entry shorter than eight
  characters, such as `"Bash"`, or one written more than once still gets no
  line rather than a guessed one. The findings, their severities and their
  count are unchanged.
