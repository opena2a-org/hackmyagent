# Plugin API

Build custom security plugins for HackMyAgent. Every plugin implements the `OpenA2APlugin` interface: `scan()` to find issues, `fix()` to remediate them, and optionally `monitor()` for continuous protection.

## Quick Start

```typescript
import { registerPlugin, type OpenA2APlugin, type Finding, type Remediation } from 'hackmyagent';

const myPlugin: OpenA2APlugin = {
  metadata: {
    packageName: 'my-security-plugin',
    displayName: 'My Security Plugin',
    description: 'Checks for custom security patterns',
    version: '1.0.0',
    findings: ['CUSTOM-001', 'CUSTOM-002'],
    scoreImprovement: 10,
  },

  async init() {},

  async scan(agentDir: string): Promise<Finding[]> {
    // Your detection logic here
    return [{
      id: 'CUSTOM-001',
      title: 'Custom issue found',
      description: 'Description of the issue',
      severity: 'high',
      filePath: 'config.json',
      autoFixable: true,
    }];
  },

  async fix(agentDir: string, options?: { dryRun?: boolean }): Promise<Remediation[]> {
    // Your remediation logic here
    return [{
      findingId: 'CUSTOM-001',
      description: 'Fixed the issue',
      filesModified: ['config.json'],
      rollbackAvailable: true,
    }];
  },

  async status() {
    return { name: 'my-security-plugin', version: '1.0.0', active: true, findingsCount: 0 };
  },
};

registerPlugin(myPlugin);
```

## Plugin Interface

```typescript
interface OpenA2APlugin {
  readonly metadata: PluginMetadata;
  init(options?: PluginInitOptions): Promise<void>;
  scan(agentDir: string): Promise<Finding[]>;
  fix(agentDir: string, options?: FixOptions): Promise<Remediation[]>;
  status(): Promise<PluginStatus>;
  monitor?(): Promise<void>;   // Optional: continuous monitoring
  stop?(): Promise<void>;      // Optional: stop monitoring
  uninstall?(agentDir: string): Promise<void>;  // Optional: clean removal
}
```

## Types

### Finding

```typescript
interface Finding {
  id: string;           // Unique ID (e.g., "CUSTOM-001")
  title: string;        // Human-readable title
  description: string;  // Detailed description
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  filePath?: string;    // File where the issue was found
  line?: number;        // Line number
  oasbControl?: string; // OASB control ID (e.g., "1.1")
  autoFixable: boolean; // Whether fix() can remediate this
}
```

### Remediation

```typescript
interface Remediation {
  findingId: string;        // Which finding was fixed
  description: string;      // What was done
  filesModified: string[];  // Files changed
  rollbackAvailable: boolean;
}
```

### PluginMetadata

```typescript
interface PluginMetadata {
  packageName: string;     // npm package name
  displayName: string;     // Human-readable name
  description: string;     // Short description
  version: string;
  findings: string[];      // Finding IDs this plugin addresses
  scoreImprovement: number; // Score boost when all findings are fixed
}
```

### PluginInitOptions

```typescript
interface PluginInitOptions {
  aimCore?: AIMCore;                  // Optional: AIM identity integration
  config?: Record<string, unknown>;   // Plugin-specific config
}
```

## Registry Functions

```typescript
import { registerPlugin, getPlugin, listPlugins } from 'hackmyagent';

registerPlugin(myPlugin);           // Register a plugin
const plugin = getPlugin('my-plugin'); // Get by package name
const all = listPlugins();           // List all registered plugins
```

## Built-in Plugins

HackMyAgent ships with 3 built-in plugins:

| Plugin | Factory | What it does |
|--------|---------|-------------|
| Credential Protection | `createCredVaultPlugin()` | Scan for hardcoded secrets, replace with env var references |
| AI Visibility Protection | `createSecretlessPlugin()` | Block .env from AI tools, encrypt MCP server keys |
| File Signing | `createSigncryptPlugin()` | Sign skill and heartbeat files with Ed25519 |
| Skill Safety Scanner | `createSkillguardPlugin()` | Detect dangerous patterns (RCE, exfiltration, reverse shells) and pin hashes |

```typescript
import {
  createCredVaultPlugin,
  createSecretlessPlugin,
  createSigncryptPlugin,
  createSkillguardPlugin,
} from 'hackmyagent';

const credProtection = createCredVaultPlugin();
const aiVisibility = createSecretlessPlugin();   // requires secretless-ai at runtime
const fileSigning = createSigncryptPlugin();
const skillSafety = createSkillguardPlugin();
```

## AIM Integration

When `aimCore` is provided in `PluginInitOptions`, plugins gain:
- Identity-aware audit logging (who fixed what)
- Capability policy checks (what the plugin is allowed to do)
- Trust score contributions

```typescript
import { AIMCore } from '@opena2a/aim-core';

const aim = new AIMCore({ agentName: 'my-agent' });

await myPlugin.init({ aimCore: aim });
const findings = await myPlugin.scan('/path/to/agent');
```
