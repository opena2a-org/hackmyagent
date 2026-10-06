---
type: fixed
---
#### `secure` no longer stalls on a skill, SOUL.md or script line that repeats the start of a `word.*word` pattern

- Twenty patterns in `secure` look for two or three words in order on one
  line: the wallet file, seed phrase and private key patterns of SKILL-005,
  the python and perl socket patterns of SKILL-008 (also read by the SKILL-006
  bundle check), the download-paste-terminal and `.exe` patterns of
  SUPPLY-007, the special-token pattern of CONFIG-002 and CONFIG-005, the
  command-line credential patterns of NEMO-004, the install-into-`/tmp/`
  pattern of NEMO-006, and five capability patterns of SOUL-CONSENT. A line
  that repeated the first words without the last slowed each of them with the
  square of the line's length, or the cube with three words. Twelve 10,000
  character lines of `python socket ` in a SKILL.md took 10.8 seconds in the
  skill checks, one 16 KiB line of `download paste ` took 2.7 seconds in
  SUPPLY-007, and 64 KiB of `<|` in a SOUL.md took 1.7 seconds in CONFIG-002.
  Each now takes a few milliseconds, and the checks report the same findings,
  lines and quoted matches as before.
