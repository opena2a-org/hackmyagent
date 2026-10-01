---
type: fixed
issue: 608
---
#### `atomicFix` is false when a fix in the same run was disproved (#608)

- **`secure --fix --format json` reported `atomicFix: true` on a run whose verification
  pass disproved one of its fixes** (`fixed: true, fixVerified: false` on a finding in the
  same document). The flag is documented as "True if all fixes completed atomically", but
  it read the bare attempt flag. It now counts only confirmed fixes (`confirmedFix`, the
  predicate the #274 counts use) and is false when any attempt was disproved. Scores,
  findings and exit codes are unchanged.
