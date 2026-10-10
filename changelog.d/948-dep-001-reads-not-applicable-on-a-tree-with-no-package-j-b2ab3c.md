---
type: fixed
issue: 948,751,944
breaking: true
---
#### `DEP-001` reads not applicable on a tree with no `package.json` (#751, #944)

- `secure` reported `DEP-001` at MEDIUM (`Dependency Lock File`, naming
  `package-lock.json`) on a tree that holds no `package.json`, advising a lock
  file for dependencies the tree never declared. On 0.33.2 an empty directory
  and a Homebrew tap holding a README, a Ruby formula and a shell script each
  scored 93/100 with that finding shown. Both now score 98/100 with no
  `DEP-001` finding. In `--json`, `allFindings` carries one `DEP-001` record
  whose `notApplicable.subject` is `package.json`, with no `severity`, `file`
  or `passed`.
- This release is the first to carry the change. 0.33.0 listed the finding
  under Known issues and 0.33.2 stated that it still fires (#751); 0.33.2 was
  cut without the change, and no published version includes it. `DEP-001` on
  such a tree in 0.33.0 or 0.33.2 (#944) is that known issue as published, not
  a fix that stopped working.
- The exit code of `secure -b oasb-1` moves on both trees. OASB-1 controls
  6.1 to 6.4 all read `DEP-001`, so on 0.33.2 each tree printed
  `Rating: Not Passing` and `Compliance: 43% (3/7 verified controls)` and
  exited 1. The four controls now read not applicable: the tap prints
  `Rating: Certified` and `Compliance: 100% (3/3 verified controls)` and exits
  0, and the empty directory prints `Rating: Not Assessed` and exits 2,
  because no file was read from it.
- A tree with a `package.json` is unchanged. One holding only a `package.json`
  still reports `DEP-001` at MEDIUM and scores 93/100, and adding a
  `package-lock.json` passes the check at 98/100.
