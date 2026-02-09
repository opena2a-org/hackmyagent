# @opena2a/signcrypt-openclaw

[![npm version](https://img.shields.io/npm/v/@opena2a/signcrypt-openclaw.svg)](https://www.npmjs.com/package/@opena2a/signcrypt-openclaw)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Configuration integrity plugin for HackMyAgent. Ed25519 signing, DNS publisher verification, and heartbeat expiry enforcement.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

## Install

```bash
npm install @opena2a/signcrypt-openclaw
```

## Usage

```typescript
import { createPlugin } from '@opena2a/signcrypt-openclaw';
import { registerPlugin } from '@opena2a/plugin-core';

const plugin = createPlugin();
registerPlugin(plugin);

// Scan for configuration integrity issues
const findings = await plugin.scan('/path/to/project');
```

## What It Does

- **Ed25519 signing** — Signs configuration files so tampering is detected
- **DNS publisher verification** — Verifies that plugins and skills come from their claimed publisher via DNS TXT records
- **Heartbeat expiry** — Enforces time-based configuration expiry so stale configs are flagged

## Related

- [`@opena2a/plugin-core`](https://www.npmjs.com/package/@opena2a/plugin-core) — Plugin interface
- [`@opena2a/skillguard-openclaw`](https://www.npmjs.com/package/@opena2a/skillguard-openclaw) — Skill integrity
- [`hackmyagent`](https://www.npmjs.com/package/hackmyagent) — Full security toolkit

## License

Apache-2.0
