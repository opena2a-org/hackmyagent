---
type: fixed
issue: 660
---
#### `attack -H` can be repeated (#660)

- **Every `-H/--header` reaches the target.** The help said the flag "can be used multiple
  times", but it was registered without a collector, so a repeated `-H` overwrote the previous
  one and only the last header was sent. Repeats now accumulate.
