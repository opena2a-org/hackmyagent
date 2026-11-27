---
type: fixed
---
#### `secure -b` names the controls `--ignore` and `.hmaignore` left unscored

- On a package manifest with no lock file, `secure -b oasb-1 --ignore DEP-001` dropped controls 6.1 to 6.4 from the compliance figure and the rating, and the text report said nothing about it. The benchmark now reads what `--ignore`, `.hmaignore` check rules and `.hmaignore` path rules set aside. A control one of those checks maps to is never credited: unless another of its checks failed it, it is `unverified`, outside every figure, and marked suppressed.
- The text report names each such control with the check and the flag or rule that set it aside (`[s] 6.1: ... (suppressed: DEP-001 by --ignore)`), adds the count to the Rating, Compliance and category lines, lists the withheld findings, and no longer shows a category as passed while one of its controls is suppressed. A line on stderr beside the exit gates says the compliance figure, the rating and `--fail-below` were computed without them.
- `--json` marks each such control with `suppressed` (`checkIds`, `suppressedBy`, `findings`), counts them in `suppressedControls` and in each category's `suppressed`, and keeps the `suppressed` and `outOfScope` rows. `-b oasb-2 --json` now carries those rows too. A run with nothing set aside produces the same document as before.
