---
type: fixed
issue: 1013
breaking: true
---
#### scan-soul reports a profile that a keyword in the text narrowed (#1013)

- With no `<!-- soul:profile=... -->` marker and no `--profile` flag,
  scan-soul picks the profile from keywords it matches as substrings
  (`chat`, `assistant`, `code`). One sentence such as "Users reach it over
  chat." turned a SOUL.md whose headings describe a tool-using agent into a
  `conversational` scan that skipped Capability Boundaries, Trust Hierarchy,
  Data Handling and Human Oversight, and nothing said so: `profileMismatch`
  was only computed for a marker or a flag.
- It is now computed whatever set the profile. A keyword-detected profile
  narrower than the body raises the HIGH `SOUL-PROFILE-MISMATCH`, which clamps
  the score below HARDENED and makes `scan-soul --ci` exit 1, where it could
  exit 0 before. The `--json` finding carries a new `source` field (`marker`,
  `flag` or `keywords`), and the text report names a marker that sets the
  profile the body describes.
