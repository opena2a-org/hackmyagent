---
type: fixed
---
- `hackmyagent explain <id>` answers every check `check-metadata` lists with
  the check's name, what it detects, why it matters and its fix. Before, 260
  of the 306 ids printed only a "<Category> finding." line, for example
  "Security check finding." for `explain CLAUDE-004`. A check whose findings
  state no fix says so and names the scan that shows each finding with its
  file and message. `check-metadata --json` names each check instead of
  repeating its id. `explain` on CRED-003, CRED-004, MCP-001, SKILL-005,
  PERM-001, PERM-002, PERM-003 and SUPPLY-001 now describes the check
  `secure` reports under that id; the previous text described other checks.
