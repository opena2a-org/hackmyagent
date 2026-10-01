---
type: fixed
issue: 452
---
#### `secure -f sarif` emits one rule descriptor per rule (#452)

- **The SARIF rule table no longer repeats a rule.** `tool.driver.rules` was built one
  descriptor per result, so a check that fired twice emitted two identical descriptors, and
  SARIF 2.1.0 declares `rules` `uniqueItems`: the document validated on a target where every
  check fired once and failed on a real one (117 descriptors for 50 rule ids on the malicious
  corpus fixture), which GitHub's SARIF upload rejects. The table now holds one descriptor per
  check id, at the highest severity any of its results carries, and every result points at
  its rule by `ruleIndex`. Each result keeps its own level and message. Tests:
  `__tests__/cli/sarif-unique-rules.test.ts`.
