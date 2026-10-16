---
type: fixed
issue: 1119
---
#### secure names each byte-identical file in its own findings (#1119)

- When two scanned files of the same type had exactly the same bytes, the
  second file was served the first file's compiled result, which carried the
  first file's path, so `secure` reported the second file's findings under
  the first file's name and then merged them away. With two identical skill
  files, `a.skill.md` and `b.skill.md`, AST-GOV-001, AST-GOV-003 and
  AST-GOV-004 named only `a.skill.md`. Each file's findings now carry the
  path of the file that was read, and the same scan names both files.
