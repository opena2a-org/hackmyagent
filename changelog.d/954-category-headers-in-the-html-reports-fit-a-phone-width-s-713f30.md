---
type: fixed
issue: 954
---
#### Category headers in the HTML reports fit a phone-width screen (#954)

- In the HTML reports from `benchmark` and `attack`, opened at a 375px-wide
  screen, a category header ran past the right edge of its card: the name,
  score, bar and chevron stayed on one line. The header now wraps: the name
  breaks onto more lines, and the score, bar and chevron move to a line of
  their own when the name has less than about 8rem. Below 480px the header's
  padding is smaller and the report's top header wraps too.
