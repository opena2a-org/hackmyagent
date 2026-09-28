---
type: fixed
issue: 524
---
#### A fix citation of the finding's own file runs from where the reader stands (#524)

- **`SUPPLY-001`'s `hackmyagent check SKILL.md` is rebased onto the scan root in text output.**
  The operand was relative to the scanned target, so `secure ./skill-out` run from the parent
  printed a command that failed on paste with `Invalid skill identifier`. The text renderer now
  joins the scan root onto a citation whose operand is exactly the finding's own file, the same
  join the `Verify:` line has used since #286: measured, the same run now prints
  `hackmyagent check <abs>/skill-out/SKILL.md`, which runs from the parent. Any other operand is
  left as authored, and JSON `fix` fields stay target-relative. Regression:
  `__tests__/ui/own-file-citation-rebase.test.ts`, `__tests__/cli/own-file-fix-citation-runnable.test.ts`.
