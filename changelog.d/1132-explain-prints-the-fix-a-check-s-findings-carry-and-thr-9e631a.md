---
type: fixed
issue: 1132
---
#### explain prints the fix a check's findings carry, and three printed commands fail closed when pasted (#1132)

- `hackmyagent explain DEP-004` printed `npm install --save-exact <package>`
  while the finding `secure` reports carried
  `npm install --save-exact "${PACKAGE:?set PACKAGE to the package the script installs}"`.
  It now prints the finding's fix.
- `explain` on the 23 scan-soul controls whose ids start SOUL-TH, SOUL-CB,
  SOUL-IH, SOUL-DH, SOUL-HB, SOUL-AS, SOUL-HT, SOUL-HO and SOUL-HV, and on
  CRED-001, CRED-002, NEMO-005, NEMO-006, NEMO-007, AST-CRED-001,
  AST-CRED-002, AST-CRED-003, AST-GOV-001, AST-GOV-002, AST-INJECT-001,
  AST-PROMPT-001, AST-PROMPT-003, TEXT-001 and TEXT-002, printed no fix line
  and no statement that none is recorded. Each now prints a `Fix:` line with
  the fix its findings carry (with `<file>` where a finding names its file),
  and a `Why it matters:` line where the check records a reason. Their
  descriptions no longer name a fix of their own: `explain AST-CRED-001`
  named `opena2a protect .`, while its findings say "Never request, store, or
  retransmit credentials."
- `hackmyagent trust --batch` printed `npx hackmyagent check <name>` and
  `npx hackmyagent trust <name>` as next steps, and `secure` printed
  `https://<host>/<org>/<repo>.git` in the command to run when the git
  remote origin is a local path. Pasted, the first two were a syntax error
  in bash, zsh and dash, and the shell read the third's `<host>`, `<org>`
  and `<repo>` as file redirections. Each operand is now written
  `"${NAME:?set NAME to ...}"`, so bash, zsh and dash stop with that message
  when it is unset and run nothing.
