---
type: fixed
issue: 423
---
#### A file is scanned as a skill whenever its frontmatter declares capabilities, in any valid YAML spelling (#423)

- The AST checks that `secure` runs now load a file's leading frontmatter as
  YAML before deciding whether the file is a skill. A `capabilities` key nested
  under `metadata:`, written as a quoted key, inside an indented block, after a
  byte-order mark or blank lines, or in a block closed by `----`, `--- end` or
  `...` was read as an ordinary document and skipped the skill checks. These
  files are now scanned as skills. Frontmatter that does not parse as YAML but
  has a `capabilities:` line is also scanned as a skill.
- `capabilities: [run_shell, read_files]` was read as one string, so a skill
  written that way produced fewer findings than the same skill written as a
  block list, with no `AST-CAP-002`. Both spellings now declare the same
  capabilities and produce the same findings.
- A document that opens with a horizontal rule and has a prose line starting
  `capabilities:` is no longer scanned as a skill. That removes a false
  CRITICAL `AST-EXFIL-001` on a placeholder URL in such a document.
