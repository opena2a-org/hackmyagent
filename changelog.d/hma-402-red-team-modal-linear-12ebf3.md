---
type: fixed
issue: 402
---
#### `red-team` reads a modal-dense artifact in linear time (#402)

- **The modal-statement extraction no longer backtracks quadratically.** It was
  `content.match(/(?:must|...|restricted)[^.]+\./gi)`: every keyword with no `.` after it
  consumed the rest of the input and backtracked, so an artifact of modal keywords with no
  sentence terminator stalled `red-team` with no timeout. Measured on this change's parent
  with `"must never always "` repeated to 1 MiB, the largest input the report boundary passes
  to the extractor: 75.2 s for the match alone. The extraction now finds each keyword, looks
  up the next `.` once, and stops at the first keyword with no `.` after it: under 1 ms on
  the same input. The statements it returns are unchanged: a seeded differential test pins
  the new extraction to the old match on 3,000 inputs, and a timing probe at 1 MiB pins the
  bound. Tests: `__tests__/attack-engine/target-reader-modal-linear.test.ts`.
