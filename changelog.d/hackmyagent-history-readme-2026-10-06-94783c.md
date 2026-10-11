---
type: added
---
#### The README and the CI guide document `secure --scan-history`, and the release smoke walks it

- The README's CI/CD integration section named `--range` and not `--scan-history`. It now has a
  subsection for it: check out with `fetch-depth: 0` (a one-commit checkout reads that one commit
  only), each credential is reported once as `CRED-HIST-001` cited `<commit>:<file>:<line>`, rotate
  the value at its issuer first, and `--since <ref>` bounds later runs.
  `docs/use-cases/ci-pipeline.md` carries the workflow, a sample finding and the key shapes the
  pass matches.
- `docs/testing/release-smoke.md` gains step 6.6. It builds a throwaway repository whose key was
  added in one commit and deleted in the next, and checks the built CLI: exit 0 without the flag;
  exit 1 with the flag and one finding at the commit that added the key; the printed `Verify:`
  command returns the line; the value appears in none of the text, `--json` or SARIF output;
  `--since` the adding commit reads only the deletion; and a directory outside a git work tree is
  refused.
