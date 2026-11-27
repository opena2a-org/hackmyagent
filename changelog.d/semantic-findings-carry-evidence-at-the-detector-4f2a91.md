---
type: fixed
---
- SEM-MCP-001, 002, 003, 004, 007 and 008, SEM-PERM-001 and 003, and SEM-CRED-004
  now record the line they are about as evidence, the way SEM-CRED-001 does, so
  each shows `<file>:<line>` and a `Verify:` command. SEM-MCP-001, 002 and 003
  cite the line of the argument itself rather than the first line of the file
  that contains the same text, and SEM-PERM-001 and 003 cite the entry in
  `permissions.allow` by position. The recorded line has secret values
  replaced by `[REDACTED]`. SEM-MCP-005, SEM-MCP-006, SEM-INST-003,
  SEM-INST-004 and SEM-PERM-002 describe a set of servers, a whole file or the
  absence of a restriction, not one line, and stay without a line.
