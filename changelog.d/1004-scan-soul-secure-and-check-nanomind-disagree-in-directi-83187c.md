---
type: known-issue
issue: 1004
---
- `scan-soul`, `secure` and `check --nanomind` disagree in direction on a
  SOUL.md that writes its role-play refusal as prose. On the corpus fixture
  `soul/benign/hardened-soul`, `scan-soul` reports Governance 19/100, Level
  NONE, and exits 1, with the critical control `SOUL-IH-003` (Role-play
  refusal) not detected; `secure <dir>` and `check <dir> --nanomind` report
  98/100 on the same directory and exit 0. `SOUL-IH-003` is detected by
  keyword match, so a file that forbids altering the agent's identity in other
  words is reported as missing the control. `scan-soul` says so under
  `Detection` and prints a clause that satisfies the match under `By hand:`.
  Appending that clause to the fixture's SOUL.md takes `scan-soul` to exit 0
  (Level PARTIAL ESSENTIAL, 18/100, read as the `conversational` profile with
  4 of 9 domains evaluated) and leaves `secure` at 98/100; that is the
  measured workaround. Present in 0.33.2, where `scan-soul` prints the same
  score, level and exit code and `secure` exits 0 at 93/100; the `scan-soul`
  half is listed under the 0.30.0 Known issues. Target 0.35.0
  ([#1004](https://github.com/opena2a-org/hackmyagent/issues/1004)).
