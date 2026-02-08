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

export interface SignatureRecord {
  /** File or config that was signed */
  target: string;
  /** Ed25519 signature (base64) */
  signature: string;
  /** Signer's public key (base64) */
  signerPublicKey: string;
  /** ISO timestamp of signing */
  signedAt: string;
  /** Expiry timestamp (max 7 days for heartbeats) */
  expiresAt?: string;
}

export interface PublisherVerification {
  /** Publisher domain (e.g., "acme.com") */
  domain: string;
  /** DNS TXT record key */
  txtRecordKey: string;
  /** Expected public key from DNS */
  expectedPublicKey: string;
  /** Whether verification passed */
  verified: boolean;
}

export interface SignCryptConfig {
  /** Directory for signature store. Defaults to <agentDir>/.opena2a/signcrypt */
  dataDir?: string;
  /** Maximum heartbeat signature age in seconds. Default: 604800 (7 days) */
  maxHeartbeatAge?: number;
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: '@opena2a/signcrypt-openclaw',
  displayName: 'SignCrypt',
  description: 'Configuration integrity — Ed25519 signing, DNS publisher verification, heartbeat expiry',
  version: VERSION,
  findings: ['SIGN-001', 'SIGN-002', 'SIGN-003', 'SIGN-004'],
  scoreImprovement: 8,
};

export class SignCryptPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private config: SignCryptConfig = {};

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.config = (options?.config as SignCryptConfig) ?? {};
  }

  async scan(agentDir: string): Promise<Finding[]> {
    // TODO: Implement — check for unsigned configs, expired heartbeat signatures,
    // unverified publisher DNS records, missing signature chain
    throw new Error('Not implemented');
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    // TODO: Implement — sign configs with agent's Ed25519 key,
    // set up heartbeat expiry enforcement, configure DNS verification
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
    // TODO: Implement — watch for config changes, re-sign on modification,
    // alert on expired signatures
    throw new Error('Not implemented');
  }

  async stop(): Promise<void> {
    // TODO: Implement — stop watchers
  }

  async uninstall(agentDir: string): Promise<void> {
    // TODO: Implement — remove signatures, revert to unsigned configs
    throw new Error('Not implemented');
  }
}

/** Create a new SignCrypt plugin instance */
export function createPlugin(): SignCryptPlugin {
  return new SignCryptPlugin();
}
