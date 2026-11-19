---
type: security
---
#### `@opena2a/shared` is no longer a dependency; hackmyagent keeps its contribution settings itself

- `@opena2a/shared` is no longer a dependency of hackmyagent. hackmyagent reads
  and writes its contribution settings in `~/.opena2a/config.json` itself,
  with the same fields: `contribute.enabled`, `contribute.consentedAt` and
  `contribute.consentVersion`, and the scan count and tip dismissal under
  `telemetry`. A config directory hackmyagent has to create is readable by its
  owner only (0700), and the file stays 0600.
- The installed tree no longer carries a zod below 4.6.6
  (GHSA-mrhx-c7xc-m3w5).
- The contribution tip is not shown again after an explicit yes or no.
