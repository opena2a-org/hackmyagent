# @opena2a/credvault-openclaw

[![npm version](https://img.shields.io/npm/v/@opena2a/credvault-openclaw.svg)](https://www.npmjs.com/package/@opena2a/credvault-openclaw)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Credential protection plugin for HackMyAgent. Encrypted local secret store, environment variable resolution, and per-skill isolation. Credentials never touch the LLM context window.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

> **Looking for the standalone CLI?** See [`secretless-ai`](https://www.npmjs.com/package/secretless-ai) — one command to keep secrets out of any AI coding tool.

## Install

```bash
npm install @opena2a/credvault-openclaw
```

## Usage

```typescript
import { createPlugin } from '@opena2a/credvault-openclaw';
import { registerPlugin } from '@opena2a/plugin-core';

const plugin = createPlugin();
registerPlugin(plugin);

// Scan for credential issues
const findings = await plugin.scan('/path/to/project');

// Each finding includes:
// - patternName: 'Anthropic API Key', 'AWS Access Key', etc.
// - file: where the credential was found
// - severity: 'critical' or 'high'
// - remediation: how to fix it
```

## What It Does

- Scans project files for hardcoded credentials (API keys, tokens, passwords)
- Provides an encrypted local store for secrets
- Resolves credentials via environment variables at runtime
- Isolates secrets per-skill so plugins only access what they need

## Credential Patterns

Detects Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, SendGrid, Supabase, and Azure credentials.

## Related

- [`secretless-ai`](https://www.npmjs.com/package/secretless-ai) — Standalone CLI for protecting AI coding tools
- [`@opena2a/plugin-core`](https://www.npmjs.com/package/@opena2a/plugin-core) — Plugin interface
- [`hackmyagent`](https://www.npmjs.com/package/hackmyagent) — Full security toolkit

## License

Apache-2.0
