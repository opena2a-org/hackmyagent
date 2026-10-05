---
type: added
issue: 536
---
#### `secure --scan-history` reports credentials committed to git history, including ones since deleted from the tree (#536)

- `secure` read only the checked-out tree, so a key that was committed and
  then deleted scored clean (98/100, exit 0) while every clone still held it.
  `secure --scan-history` also reads every commit reachable from any ref
  (branches, tags, remote-tracking refs), and reports each credential once,
  at the commit that added it, as `CRED-HIST-001` (critical) cited `<commit>:<file>:<line>`.
- A history hit gets the treatment a tree hit gets for the same path and
  value. A line added to a test file (`*.test.ts`, `*.spec.js`, `_test.go`,
  `__tests__/`) is not reported, and neither is a value carrying a fixture
  marker such as `FAKE` or `EXAMPLE` or a placeholder word such as
  `changeme`. A real-shaped key added and then deleted in `src/config.ts`
  stays critical.
- The fix line says to rotate the credential, since editing the tree does
  not change a commit, and the `Verify:` line reads the line from the commit
  (`git -C <dir> show <commit>:./<file> | sed -n '<line>p'`). `--json` adds a
  `commit` field to the finding and a `history` summary with the number of
  commits read; SARIF results carry the commit in `properties`.
- `--since <ref>` reads only commits not reachable from `<ref>`. The run is
  refused before scanning when the target is not in a git work tree, the ref
  does not resolve, or `-b` is given.
