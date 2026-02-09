# @opena2a/skillguard-openclaw

[![npm version](https://img.shields.io/npm/v/@opena2a/skillguard-openclaw.svg)](https://www.npmjs.com/package/@opena2a/skillguard-openclaw)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Skill integrity plugin for HackMyAgent. Hash pinning, filesystem watcher, sandbox enforcement, and tamper detection.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

## Install

```bash
npm install @opena2a/skillguard-openclaw
```

## Usage

```typescript
import { createPlugin } from '@opena2a/skillguard-openclaw';
import { registerPlugin } from '@opena2a/plugin-core';

const plugin = createPlugin();
registerPlugin(plugin);

// Scan for skill integrity issues
const findings = await plugin.scan('/path/to/project');
```

## What It Does

- **Hash pinning** — Pins skill files by SHA-256 hash so modifications are detected
- **Filesystem watcher** — Monitors skill directories for unauthorized changes at runtime
- **Sandbox enforcement** — Verifies skills run within their declared capability boundaries
- **Tamper detection** — Alerts when skill files have been modified since last verification

## Related

- [`@opena2a/plugin-core`](https://www.npmjs.com/package/@opena2a/plugin-core) — Plugin interface
- [`@opena2a/signcrypt-openclaw`](https://www.npmjs.com/package/@opena2a/signcrypt-openclaw) — Configuration integrity
- [`hackmyagent`](https://www.npmjs.com/package/hackmyagent) — Full security toolkit

## License

Apache-2.0
