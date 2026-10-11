---
type: fixed
issue: 978
---
#### The OpenClaw check tables in docs/SECURITY_CHECKS.md describe the checks each id reports (#978)
- The SKILL, HEARTBEAT, GATEWAY, CONFIG and SUPPLY tables named a different
  check for most ids (GATEWAY-002 was listed as an open gateway port; the
  scanner reports it as Missing WebSocket Origin Validation) and gave
  severities and fixability the scanner does not report. Each row now carries
  the check name, severity and fixability the scanner reports for that id.
  The SKILL-020 row gives both names the scanner reports it under, Missing
  YAML Frontmatter and Incomplete Frontmatter.
- The auto-fix table listed nine ids that `--fix` does not change (SKILL-009,
  HEARTBEAT-001, HEARTBEAT-004, GATEWAY-002 and CONFIG-001, -002, -003, -005
  and -006) and left out SKILL-004 and GATEWAY-004. It now lists the seven ids
  `--fix` changes (SKILL-004, SKILL-019, HEARTBEAT-007, GATEWAY-001,
  GATEWAY-003, GATEWAY-004 and GATEWAY-005) with the change it makes for each.
