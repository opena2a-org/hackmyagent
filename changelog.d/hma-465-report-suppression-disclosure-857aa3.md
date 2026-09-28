---
type: fixed
issue: 465
---
#### SARIF, HTML and ASFF reports disclose suppressed and out-of-scope findings (#465)

- **The report files paired a corrected score and exit code with an uncorrected list.** After
  #450, `--ignore` and `.hmaignore` findings still count toward the score and the exit code,
  and the terminal report names them, but the file writers were never handed the two
  records. With `.hmaignore` holding `vendor/` and `!DEP-001`, `-f sarif` had no
  `run.properties`, `-f html` no suppression text, and `-f asff` nothing at all.
  - SARIF: `runs[0].properties.suppressed` and `runs[0].properties.outOfScope`, the same
    identity-only rows `secure --json` carries.
  - HTML: a "Suppressed and out of scope" section, in the terminal report's wording, with
    one row per check.
  - ASFF: the format is a bare array of findings, so the disclosure goes to stderr beside
    the import instructions; stdout stays importable.
- **Each `.hmaignore` rule in `--json` names the findings it excluded.** `hmaignore.rules[]`
  entries gain `excluded: [{ checkId, severity, file }]`, one per matched finding, so a
  reviewer can tell which rule excluded which critical. The `outOfScope` rows stay
  identity-only, because they travel with a published result; the per-rule record is local
  and never rides a wire.
