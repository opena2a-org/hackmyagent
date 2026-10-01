---
type: fixed
issue: 370
---
#### No raw credential in any `secure` output format, measured on the built CLI (#370)

- **Regression test for #370.** `secure --json` once emitted a GitHub token verbatim in
  `evidence.lines[].content` while redacting a connection-string password in the same
  line. Redaction at the finding construction boundary already removes both; this adds the
  test the issue asked for. `__tests__/cli/evidence-redaction-every-format.test.ts` spawns
  the built CLI over the issue's fixture (two credential shapes on one line, from an empty
  `HOME`) and asserts neither raw value reaches the output of `--json`, text, `--verbose`
  text, `--format sarif`, `--format html`, `--format asff` or `-b oasb-1 --format json`.
  Each format must also render the credential file, so a format that drops the finding
  cannot pass by printing nothing. With the boundary's `evidence.lines[].content` redaction
  removed, both JSON cases fail. No scanner behaviour changes.
