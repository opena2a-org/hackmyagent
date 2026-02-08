export const VERSION = '0.1.0';

import type {
  OpenA2APlugin,
  PluginMetadata,
  PluginStatus,
  Finding,
  Remediation,
  FixOptions,
  PluginInitOptions,
} from '@opena2a/plugin-core';
import type { AIMCore } from '@opena2a/aim-core';

// --- Types ---

export interface SecretEntry {
  /** Secret path (e.g., "stripe-api-key", "db-prod/password") */
  path: string;
  /** Which skills can access this secret */
  allowedSkills: string[];
  /** Backend this secret is resolved from */
  backend: 'local' | 'env' | 'vault' | 'aws-sm' | '1password' | 'azure-kv' | 'gcp-sm';
  /** ISO timestamp of last rotation */
  lastRotated?: string;
}

export interface SecretBackend {
  /** Resolve a secret by path */
  resolve(secretPath: string): Promise<Record<string, string>>;
  /** Check if the backend is reachable */
  healthCheck(): Promise<boolean>;
}

export interface SecretlessConfig {
  /** Directory for encrypted local store. Defaults to <agentDir>/.opena2a/secretless */
  dataDir?: string;
  /** Default backend for secret resolution */
  defaultBackend?: SecretEntry['backend'];
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: '@opena2a/secretless-openclaw',
  displayName: 'Secretless',
  description: 'Credential protection — encrypted local store, env var resolution, per-skill isolation',
  version: VERSION,
  findings: ['CRED-001', 'CRED-002', 'CRED-003', 'CRED-004', 'CRED-005'],
  scoreImprovement: 25,
};

export class SecretlessPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private config: SecretlessConfig = {};

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.config = (options?.config as SecretlessConfig) ?? {};
  }

  async scan(agentDir: string): Promise<Finding[]> {
    // TODO: Implement — scan for hardcoded credentials in config files,
    // env vars in context, unencrypted secrets, missing per-skill isolation
    throw new Error('Not implemented');
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    // TODO: Implement — move hardcoded secrets to encrypted local store,
    // configure env var resolution, set up per-skill access policies
    throw new Error('Not implemented');
  }

  async status(): Promise<PluginStatus> {
    return {
      name: metadata.displayName,
      version: metadata.version,
      active: false,
      findingsCount: 0,
    };
  }

  async monitor(): Promise<void> {
    // TODO: Implement — watch for new hardcoded credentials being added
    throw new Error('Not implemented');
  }

  async stop(): Promise<void> {
    // TODO: Implement — stop file watchers
  }

  async uninstall(agentDir: string): Promise<void> {
    // TODO: Implement — revert changes, optionally export secrets back to config
    throw new Error('Not implemented');
  }
}

/** Create a new Secretless plugin instance */
export function createPlugin(): SecretlessPlugin {
  return new SecretlessPlugin();
}
