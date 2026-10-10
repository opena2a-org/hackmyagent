---
type: added
---
#### `check-metadata --json` states each check's canonical attack class

- Every check entry carries a new `canonicalClass` key beside `attackClass`.
  Its value is one of the ten canonical attack classes (`injection`,
  `exfiltration`, `credential_abuse`, `privilege_escalation`, `persistence`,
  `lateral_movement`, `social_engineering`, `policy_violation`,
  `steganography`, `benign`). `attackClass` is unchanged: it holds the
  check's attack family (for example `MCP-EXPLOIT`), which names the surface
  the check inspects rather than the class. Before, the output held only the
  family, so a consumer that needed a class had to store the family in its
  place.
- The family codes `MCP-PRIV-ESC`, `CMD-INJECT`, `PROMPT-INJECT` and
  `PERSISTENCE` take the class of the families that hold the same conditions
  (`MCP-EXPLOIT`, `CODE-INJECTION`, `SOUL-INJECT`, `PERSIST-STATE`). So
  `MCP-001` and `SEM-MCP-001`, which both report a filesystem MCP server with
  unscoped reach, show the same class, `privilege_escalation`.
