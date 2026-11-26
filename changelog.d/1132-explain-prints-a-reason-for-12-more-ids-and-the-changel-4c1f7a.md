---
type: fixed
issue: 1132
---
#### explain prints a `Why it matters:` line for 12 more ids, and this entry names the 37 that still print none (#1132)

- `hackmyagent explain` printed no `Why it matters:` line for 49 of the 306 ids
  `check-metadata` lists. It now prints one for API-KEY-EXPOSED,
  AST-GOV-001, CLAUDE-MD-EXPOSED, CONFIG-EXPOSED, GIT-002, MCP-003, MCP-004,
  MCP-SSE, MCP-TOOLS, NEMO-009, UNICODE-STEGO-001 and UNICODE-STEGO-002. Each
  reason is the one the check's findings carry (the `guidance` text, or the
  `impact` text for the checks run against a live URL).
- These 37 ids still print no `Why it matters:` line, because their findings
  carry no reason that is the same for every finding, and `explain` does not
  make one up: AST-EXFIL-001, AST-GOV-003, AST-HEARTBEAT-001, AST-INJECT-001,
  AST-MANIP-001, AST-PERSIST-001, AST-SCOPE-004, CRED-001, PERSIST-001,
  PERSIST-002, PERSIST-003, SKILL-018, TEXT-001, TEXT-002, and the 23 scan-soul
  controls SOUL-TH-001 to SOUL-TH-005, SOUL-IH-001, SOUL-IH-002,
  SOUL-CB-001, SOUL-CB-002, SOUL-DH-001, SOUL-DH-002, SOUL-HB-001,
  SOUL-HB-002, SOUL-HT-001, SOUL-HT-002, SOUL-HO-001, SOUL-HO-002,
  SOUL-AS-001, SOUL-AS-002 and SOUL-HV-001 to SOUL-HV-004. Each still prints
  its name, description and fix line.
