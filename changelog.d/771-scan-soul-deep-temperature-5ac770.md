---
type: fixed
issue: 771
---
#### `scan-soul --deep` asks the hosted model for its most likely answer on every run (#771)

- With `ANTHROPIC_API_KEY` set, `scan-soul --deep` asks the hosted model one
  YES/NO question for each control the local tiers did not detect. The
  request did not set a temperature, so the model sampled at 1.0. A control
  near the boundary could be upgraded on one run and not on the next. On an
  unchanged file, the governance score, the conformance level and the exit
  code could then differ between consecutive runs.
- The request now sets `temperature: 0`. The hosted API does not promise
  identical answers even at 0. For a CI gate that must give the same result
  on every run, run the step with the variable unset:
  `env -u ANTHROPIC_API_KEY hackmyagent scan-soul <dir> --deep`. Without the
  variable, the local semantic pass still runs and the hosted pass is
  skipped.
