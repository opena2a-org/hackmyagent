---
type: fixed
issue: 997
---
#### The check reference gives the severities GIT-001 and GIT-002 are reported at (#997)

- `docs/SECURITY_CHECKS.md` listed GIT-001 (Missing .gitignore) as Medium and
  GIT-002 (Incomplete .gitignore) as High. `hackmyagent secure` reports both
  as `low` when no key or secrets file is at risk, and as `high` when one is
  present or the project tree is too large or deep to scan in full. The two
  entries now state both severities and the condition for each. What `secure`
  reports is unchanged.
