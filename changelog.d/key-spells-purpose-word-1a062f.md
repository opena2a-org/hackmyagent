---
type: fixed
---
#### A key is reported whatever its own characters spell

- `secure` decides whether a file is a test, an example or documentation
  partly from its declared purpose, which for a source file with no
  frontmatter is its first long line. That decision now reads the line with
  every credential-shaped value removed, so a hardcoded key whose body spells
  test, documentation, fixture or demo, in any letter case, is reported with
  AST-CRED-001 like any other key.
- A key containing EXAMPLE is still a placeholder and produces no finding, and
  a file that is a test by its path or by words outside the key keeps its
  result.
