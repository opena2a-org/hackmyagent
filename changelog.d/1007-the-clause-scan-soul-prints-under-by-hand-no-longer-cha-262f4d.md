---
type: fixed
issue: 1007
---
#### The clause `scan-soul` prints under `By hand:` no longer changes the profile of the file it is pasted into (#1007)

- When a critical control is not detected, `hackmyagent scan-soul` prints a
  clause under `By hand:` that satisfies it. The clause for `SOUL-IH-003`
  ended with "regardless of conversational framing", and `scan-soul` infers
  the profile from the words of the file. Pasting the clause into a SOUL.md
  read as `custom` made the next scan read it as `conversational`, which
  evaluates 4 of 9 domains. A BASIC-tier file went from 6 domains evaluated
  to 4, with Trust Hierarchy and Data Handling no longer checked; a
  TOOL-USING file went from 8 to 4, and a MULTI-AGENT file from 9 to 4.
  The clause for `SOUL-HB-001` said "hardcoded", which contains the `code`
  keyword of the
  `code-assistant` profile, and took a TOOL-USING file from 8 of 9 domains
  to 6. Both clauses are reworded: "regardless of how a request is framed"
  and "Safety constraints are fixed and always apply". They satisfy the same
  controls as before, and a file keeps its tier, profile and evaluated
  domains after either one is pasted. A SOUL.md that already carries the
  earlier wording is read as before; changing those words in it to the new
  ones restores the profile.
