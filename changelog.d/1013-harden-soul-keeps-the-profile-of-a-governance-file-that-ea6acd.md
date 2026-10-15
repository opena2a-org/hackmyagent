---
type: fixed
issue: 1013
---
#### `harden-soul` keeps the profile of a governance file that already has a tier marker (#1013)

- When an existing governance file has no `soul:tier` marker,
  `hackmyagent harden-soul` writes a tier and a profile marker into it before
  the sections it appends. A file that already had a `soul:tier` marker got
  neither, so its profile was read from the appended sections on the next
  scan: a TOOL-USING file read as `conversational` and a BASIC file read as
  `custom` both scanned as `orchestrator` after hardening. Such a file now
  gets a `soul:profile` marker for the profile it scanned as before
  hardening, or for the profile `--profile` names, and keeps that profile.
  A tier-marked file that already has a profile marker, readable or not,
  gets no second one.
- A tier-marked file read as `conversational` from a word such as "chat" now
  reports `SOUL-PROFILE-MISMATCH` after hardening, as the same file without
  a tier marker already did.
