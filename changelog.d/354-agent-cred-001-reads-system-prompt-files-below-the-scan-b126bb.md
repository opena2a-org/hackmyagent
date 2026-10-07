---
type: fixed
issue: 354
---
#### AGENT-CRED-001 reads system-prompt files below the scan root (#354)

- `secure` checked `SOUL.md`, `CLAUDE.md`, `system-prompt.md` and
  `system-prompt.txt` for credential-protection instructions only at the scan
  root, so the same prompt was reported as `CLAUDE.md` and missed as
  `sub/CLAUDE.md`. These names are now read up to two directories down, the
  same depth AGENT-CRED-001 already used for `system-prompt.ts` and
  `system-prompt.js`. A tree whose prompt files sit only at the root is
  reported exactly as before.
