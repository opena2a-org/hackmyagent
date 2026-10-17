---
type: changed
---
#### The README's Usage section drops the `check`, governance and attack examples that "What do you want to check?" now gives, so the README is no longer than it was before that section was added

- "What do you want to check?" added 153 words to the README (1216 to 1369,
  counted with `wc -w README.md`). Usage no longer has "Check a package or
  repo before you install it", "Grade and harden governance" or "Test an
  agent with attack payloads": the chooser names `check <target>`,
  `scan-soul`, `attack <url>` and `red-team <file>`.
- `docs/commands.md` still holds what those examples said: the npm, PyPI and
  GitHub forms of `check` under "Scan anything"; `harden-soul` and the
  `scan-soul` exit 1 under "`scan-soul` and `harden-soul`"; that `red-team`
  does not run its payloads, and the line on testing only systems you own or
  have written authorisation to test, under "`red-team`" and "`attack`".
- Also removed: the sentence before the `detect` sample, which the chooser's
  "Every agent project under this folder" now says, and the line closing
  "What it finds", which repeated the Documentation entry for
  `docs/SECURITY_CHECKS.md`.
- The README is 1213 words (`wc -w`), and a test holds it at no more than
  1216.
