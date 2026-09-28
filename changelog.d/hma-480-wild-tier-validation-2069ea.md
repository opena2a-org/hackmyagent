---
type: fixed
issue: 480
---
#### `wild` refuses a `--tier`, `--timeout` or `--delay` it cannot use, and a filter that selects no page

- **`--tier` is a whole number from 1 to 10, or the run stops before any request (#480).**
  It was passed to `parseInt` unchecked: `--tier 99999` and `--tier -5` became a filter no
  attack page matches, so nothing was scanned, the empty set scored `100/100 (strong)` and
  the run exited 0; `--tier abc` became NaN, which applied no filter and ran every tier.
  Each now exits 1 with `--tier must be a whole number between 1 and 10`. The upper bound
  is the highest tier the attack catalogue publishes, and `wild --help` states it.
- **`--timeout` and `--delay` get the same check.** A non-number fell back to the default
  without saying so; `--timeout` must be at least 1 ms, `--delay` at least 0, and `--delay 0`
  now means no pause instead of the 500 ms default.
- **A valid filter that matches nothing exits 1.** `--category jailbreak --tier 7`
  (jailbreak stops at tier 5) scored the empty set `100/100` and exited 0; it now reports
  `No attack page matches --category jailbreak --tier 7`, with the number of pages the
  target listed before filtering.
- The `Category:` header line is display-escaped like the `Target:` line above it.
