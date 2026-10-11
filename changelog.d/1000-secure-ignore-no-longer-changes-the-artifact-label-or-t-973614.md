---
type: fixed
issue: 1000
---
#### `secure --ignore` no longer changes the artifact label or the Verdict wording of a finding it still scores (#1000)

- On a SOUL.md the classifier labels `malicious`, `secure <dir> --ignore CONFIG-002` printed `soul · unknown` on the Artifacts line and dropped `in SOUL.md` from the Verdict, while the Suppressed line on the same report said the finding was still scored, still in the verdict and still in the exit code. The suppressed finding's path was withheld from the two lines that read it, so the label lost its corroboration and the lead finding lost its location. Both lines now read the same as on the run without `--ignore`, and the same holds for a `!CHECK-ID` rule in `.hmaignore`. Only the suppressed finding's own entry leaves the list. The `--json` disclosure row is unchanged: it still names the check, severity and count, and no path.
