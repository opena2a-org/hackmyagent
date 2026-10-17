---
type: fixed
---
- `hackmyagent explain <id>` answers every check `check-metadata` lists with
  the check's name, what it detects and the fix its findings carry, and says
  why the check matters where the check's definition records a reason.
  Before, 260 of the 306 ids printed only a "<Category> finding." line, for
  example "Security check finding." for `explain CLAUDE-004`. A check whose
  findings state no fix says so and names the scan that shows each finding
  with its file and message. 49 of the 306 ids print no reason: the 23
  scan-soul controls whose ids start SOUL-TH, SOUL-CB, SOUL-IH, SOUL-DH,
  SOUL-HB, SOUL-AS, SOUL-HT, SOUL-HO and SOUL-HV, and CRED-001,
  UNICODE-STEGO-001, UNICODE-STEGO-002, SKILL-018, MCP-003, MCP-004,
  NEMO-009, PERSIST-001, PERSIST-002, PERSIST-003, GIT-002, API-KEY-EXPOSED,
  CONFIG-EXPOSED, CLAUDE-MD-EXPOSED, MCP-SSE, MCP-TOOLS, AST-EXFIL-001,
  AST-SCOPE-004, AST-GOV-001, AST-GOV-003, AST-HEARTBEAT-001, AST-INJECT-001,
  AST-MANIP-001, AST-PERSIST-001, TEXT-001 and TEXT-002.
  `check-metadata --json` names each check instead of repeating its id.
  `explain` on CRED-003, CRED-004, MCP-001, SKILL-005, PERM-001, PERM-002,
  PERM-003 and SUPPLY-001 now describes the check `secure` reports under that
  id; the previous text described other checks.
