---
type: fixed
---
- NEMO-002 no longer reports a CRITICAL digest-verification bypass for
  `if (!digest)` or `if (digest && …)` written as prose inside a string or
  template literal, such as a taxonomy that describes the check. The pattern
  now counts only when it occurs as code; real code that skips verification
  on a falsy digest is still reported.
