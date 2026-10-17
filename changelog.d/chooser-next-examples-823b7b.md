---
type: added
---
#### The next commands of two choices in `docs/chooser.json` carry an example: `secure --fix` and `secure <dir> --fix`, run on a copy of a committed fixture, with the exit code and the captured output held to the build

- A choice's `nextExample` names a committed fixture, the next command with
  its operand filled in and the exit code the run ends with, like `example`
  does for the choice's own command. Its output is in
  `docs/captures/<choice>-next.txt`, beside a sidecar
  `docs/captures/<choice>-next.json`.
- `secure --fix` in `test-fixtures/insecure-library` exits 1: it applies 2
  fixes, to the mode of `.env` and to `.gitignore`, and reports the 2 high
  findings that remain in `.env`. `secure malicious-skill --fix` in
  `test-fixtures/insecure-openclaw/skills` exits 1: it adds a `.gitignore` and
  reports 4 critical, 3 high and 11 medium findings.
- A `--fix` run prints where it kept its backup under HOME. Two normalizers
  apply to those runs only: the HOME folder prints as `~`, and the backup
  folder names, made from the device, inode and creation time of the copy and
  from the time of the run, print as `<directory>` and `<run>`. The sidecars
  of the four examples that were already there are unchanged.
