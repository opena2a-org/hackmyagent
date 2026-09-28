---
type: fixed
issue: 568
---
Over a tree holding an input the run could not read, the Verdict line of `secure` and `check` now leads with it (#568): `Verdict  Incomplete: src/secrets.js could not be read (EACCES). The score is an upper bound over what was read. Usable with caveats. ...`. It used to open with `Usable with caveats.` above an exit 2. Only the order of the text line moves; the score, the exit code and `--json` are unchanged, and a `Not safe` verdict keeps its own lead.
