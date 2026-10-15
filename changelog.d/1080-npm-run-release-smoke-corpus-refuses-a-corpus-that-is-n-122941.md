---
type: fixed
issue: 1080
---
#### `npm run release-smoke:corpus` refuses a corpus that is not a git clone (#1080)

- Pointed through `OPENA2A_CORPUS_PATH` at a `git archive` export of the corpus,
  the harness printed `FAIL repo/malicious/kitchen-sink` with `golden mismatch`
  and exited 1, while a git clone of the same commit passed that fixture. The
  goldens are recorded against a clone, and GIT-003 reads `.gitignore` through
  `git check-ignore`, using a text heuristic outside a git work tree. The
  harness now exits 2 before it scans, with a message naming the clone
  requirement, when the corpus has no `.git` or sits inside another git work
  tree. `docs/testing/release-smoke.md` states the requirement.
