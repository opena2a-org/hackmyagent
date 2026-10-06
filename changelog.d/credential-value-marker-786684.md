---
type: changed
---
#### The package narrative and NemoClaw findings name a credential with a labelled marker instead of a starred prefix

- The hardcoded-secret block of a package narrative showed a secret as its
  first characters followed by asterisks, such as `hf_Q7x9Z****************`;
  for a value with no recognised vendor prefix that was its first eight
  characters. It now shows the labelled marker, such as
  `Hugging Face token: [REDACTED]`, and `shownChars` is 0.
- The NemoClaw scan findings `HMA-NMC-001`, `HMA-NMC-002` and `HMA-NMC-004` read
  `Found key nvap*** in <file>`. They now read
  `Found NVIDIA API key: [REDACTED] in <file>`. `HMA-NMC-003` read
  `Container "<name>" has key nvap*** in env` and now reads
  `Container "<name>" has NVIDIA API key: [REDACTED] in env`.
- Both now use the `<label>: [REDACTED]` form that the canonical credential
  findings already print, and no part of the credential value appears.
