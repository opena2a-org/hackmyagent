---
type: changed
---
- `secure --deep` sends the skill's system prompt to the Anthropic API with a
  prompt-cache breakpoint when the behavioral simulation runs on that backend
  (used when `ANTHROPIC_API_KEY` is set and neither the local NanoMind daemon
  nor Ollama is available). Each probe for a skill reuses the same prompt, so
  later probes read it from the cache at the cached-input rate instead of the
  full input rate. Probe input is not cached. Prompts below the model's
  minimum cacheable length are sent as before, and probe results are
  unchanged.
