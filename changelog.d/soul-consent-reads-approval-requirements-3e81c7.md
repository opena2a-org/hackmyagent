---
type: fixed
---
- `secure` no longer reports SOUL-CONSENT (broad capabilities without consent
  mechanism) on a SOUL file that makes risky actions wait on the user's
  explicit approval or confirmation. The check read only the words "consent"
  and "authorize", so "I require explicit user approval before any risky
  action", "ask the user to confirm" or "never run shell commands without
  explicit user approval" counted for nothing. Negated phrasings such as "I do
  not require approval" or "I act without user approval" are still reported.
