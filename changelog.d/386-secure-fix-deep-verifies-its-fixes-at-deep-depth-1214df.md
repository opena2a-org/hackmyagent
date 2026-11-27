---
type: fixed
issue: 386
---
#### `secure --fix --deep` verifies its fixes at deep depth (#386)

- With `ANTHROPIC_API_KEY` set, `secure --fix --deep` confirmed its fixes with
  a scan at standard depth, so its fix verification could differ from what the
  next `secure --deep` reports. The verification scan now runs at the depth of
  the run, deep analysis included, and the announced score equals the next
  `secure --deep` score. The backup `--fix` writes is kept in the backup store
  outside the scanned tree, so no file of it is sent for deep analysis by
  either scan.
