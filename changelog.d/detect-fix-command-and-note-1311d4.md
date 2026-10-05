---
type: changed
breaking: true
---
#### Breaking: detect keeps a fix's command and its words apart

`detect` put words in a finding's `remediation` and printed them on the Fix
line in the command colour. For a broad permission in an AI config the whole
fix was a sentence (`Narrow .claude/settings.json:2 — replace "Bash(*)" with
...`), and for a credential in an AI config the command `opena2a protect <dir>`
had an explanation glued to it. Pasted into a shell, either one runs words as a
program and its arguments.

`remediation` in `detect --json` now holds a command or `null`, and the words
are in a new `remediationNote` field. The broad-permission finding has
`remediation: null`; the credential finding has `remediation: "opena2a protect
<dir>"` and the explanation in `remediationNote`. The same applies to each
project under `detect --workspace --json`.

In the terminal only a command takes the command colour. The credential
explanation prints on its own line under the command, so selecting the Fix line
copies the command alone. A fix that is words alone prints as plain text, and
its `Verify:` command takes the command colour, so the line styled to be copied
is always one a shell can run.
