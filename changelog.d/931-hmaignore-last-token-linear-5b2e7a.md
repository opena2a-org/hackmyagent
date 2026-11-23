---
type: fixed
---
- A `.hmaignore` line made of one long token followed by another no longer
  slows down the parser. Looking for an `expires:` attribute at the end of
  the line went back over the long token once per character, so an
  80,000-character token followed by ` b` took about 9 seconds; it now takes
  milliseconds. Which `expires:` attributes are read is unchanged.
