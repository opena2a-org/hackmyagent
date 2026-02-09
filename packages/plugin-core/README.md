# @opena2a/plugin-core

[![npm version](https://img.shields.io/npm/v/@opena2a/plugin-core.svg)](https://www.npmjs.com/package/@opena2a/plugin-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Shared plugin interface and registry for OpenA2A security plugins. Defines the contract that all HackMyAgent plugins implement.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

## Install

```bash
npm install @opena2a/plugin-core
```

## Usage

### Using existing plugins

```typescript
import { registerPlugin, getPlugin, listPlugins } from '@opena2a/plugin-core';
import { createPlugin as createSecretless } from '@opena2a/secretless-openclaw';
import { createPlugin as createSignCrypt } from '@opena2a/signcrypt-openclaw';

// Register plugins
registerPlugin(createSecretless());
registerPlugin(createSignCrypt());

// List registered plugins
const plugins = listPlugins();
// => [{ id: 'secretless', name: 'Secretless', ... }, { id: 'signcrypt', name: 'SignCrypt', ... }]

// Get a specific plugin
const secretless = getPlugin('secretless');
```

### Writing a plugin

```typescript
import type { OpenA2APlugin, PluginMetadata, Finding } from '@opena2a/plugin-core';

export const metadata: PluginMetadata = {
  id: 'my-plugin',
  name: 'My Plugin',
  version: '0.1.0',
  description: 'Does something useful',
  category: 'security',
};

export class MyPlugin implements OpenA2APlugin {
  metadata = metadata;

  async scan(projectDir: string): Promise<Finding[]> {
    // Return findings
    return [];
  }

  async fix(finding: Finding): Promise<void> {
    // Apply a fix
  }
}
```

## Types

| Type | Description |
|------|-------------|
| `OpenA2APlugin` | Interface all plugins must implement |
| `PluginMetadata` | Plugin name, version, description, category |
| `Finding` | A security issue found during scanning |
| `Severity` | `'critical' \| 'high' \| 'medium' \| 'low' \| 'info'` |
| `Remediation` | A suggested fix for a finding |

## License

Apache-2.0
