---
type: fixed
issue: 974
---
#### `secure --verbose` lists the checks that passed (#974)

- `secure --help` describes `--verbose` as showing all checks including passed
  ones, but the text report printed only the findings: `--verbose` added a check
  ID and a category to each of them and no passed check appeared. With
  `--verbose` the report now carries a `Passed checks` section after the
  findings, one line per passed check with its ID, its name and what it
  reported. These are the passed records `--json` carries under `allFindings`,
  in the same order, so a check named in `--ignore` is not listed. The report
  without `--verbose`, the score and the exit code are unchanged.
