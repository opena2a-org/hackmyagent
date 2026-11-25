---
type: fixed
---
- AIM-001 (no agent identity declaration) no longer fires on a package whose
  `package.json` keywords merely contain `agent`. Any keyword holding the
  substring, such as `ai-agent`, `user-agent` or `agentic-tools`, marked the
  package as an agent project. A keyword now counts only when it is exactly
  `agent` or `a2a`; an `agentCard` or `a2a` field in `package.json` still
  marks an agent project as before.
