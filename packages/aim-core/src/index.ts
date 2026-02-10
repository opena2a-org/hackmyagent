export const VERSION = '0.1.0';

// Re-export all types
export type {
  AIMCoreOptions,
  AIMIdentity,
  StoredIdentity,
  AuditEvent,
  AuditEventInput,
  AuditReadOptions,
  CapabilityPolicy,
  CapabilityRule,
  TrustScore,
  TrustFactors,
  TrustHints,
} from './types';

// Re-export module functions for advanced usage
export { sign, verify } from './crypto';
export { createIdentity, loadIdentity, getOrCreateIdentity } from './identity';
export { logEvent, readAuditLog, hasAuditLog } from './audit';
export { loadPolicy, savePolicy, checkCapability, hasPolicy } from './policy';
export { calculateTrust } from './trust';

// DLP module
export {
  scanText,
  maskMetadata,
  ALL_PATTERNS,
  PII_PATTERNS,
  SECRET_PATTERNS,
  mask,
  maskAll,
  getDLPAction,
  defaultDLPPolicy,
  type DLPPattern,
  type DLPMatch,
  type DLPScanResult,
  type DLPPolicy,
} from './dlp';

// --- Imports for AIMCore ---
import type {
  AIMCoreOptions,
  AIMIdentity,
  AuditEvent,
  AuditEventInput,
  AuditReadOptions,
  CapabilityPolicy,
  TrustScore,
  TrustHints,
} from './types';

import * as identity from './identity';
import * as audit from './audit';
import * as policy from './policy';
import * as trust from './trust';
import * as crypto from './crypto';

/**
 * Main entry point for aim-core.
 *
 * Provides Ed25519 identity, local audit logging, capability policy enforcement,
 * trust scoring, and cryptographic signing — all without a server or database.
 */
export class AIMCore {
  private readonly agentName: string;
  private readonly dataDir: string;
  private readonly serverUrl: string;
  private cachedPolicy: CapabilityPolicy | null = null;
  private trustHints: TrustHints = {};

  constructor(options: AIMCoreOptions) {
    this.agentName = options.agentName;
    this.dataDir = options.dataDir ?? this.defaultDataDir();
    this.serverUrl = options.serverUrl ?? '';
  }

  /** Get or create the agent's Ed25519 identity */
  getIdentity(): AIMIdentity {
    return identity.getOrCreateIdentity(this.dataDir, this.agentName);
  }

  /** Check if a capability is allowed by the current policy */
  checkCapability(capability: string, plugin?: string): boolean {
    if (!this.cachedPolicy) {
      this.cachedPolicy = policy.loadPolicy(this.dataDir);
    }
    return policy.checkCapability(this.cachedPolicy, capability, plugin);
  }

  /** Load capability policy from YAML file */
  loadPolicy(): CapabilityPolicy {
    this.cachedPolicy = policy.loadPolicy(this.dataDir);
    return this.cachedPolicy;
  }

  /** Save a capability policy to YAML file */
  savePolicy(p: CapabilityPolicy): void {
    policy.savePolicy(this.dataDir, p);
    this.cachedPolicy = p;
  }

  /** Log an audit event to the local JSON-lines file */
  logEvent(event: AuditEventInput): AuditEvent {
    return audit.logEvent(this.dataDir, event);
  }

  /** Read audit events from local log */
  readAuditLog(options?: AuditReadOptions): AuditEvent[] {
    return audit.readAuditLog(this.dataDir, options);
  }

  /** Calculate the agent's trust score based on current state */
  calculateTrust(): TrustScore {
    const hasId = identity.loadIdentity(this.dataDir) !== null;
    return trust.calculateTrust(this.dataDir, hasId, this.trustHints);
  }

  /** Provide hints from plugins to improve trust score accuracy */
  setTrustHints(hints: TrustHints): void {
    this.trustHints = { ...this.trustHints, ...hints };
  }

  /** Sign data with the agent's Ed25519 private key */
  sign(data: Uint8Array): Uint8Array {
    const secretKey = identity.getSecretKey(this.dataDir);
    if (!secretKey) {
      throw new Error('No identity found. Call getIdentity() first to generate a keypair.');
    }
    return crypto.sign(data, secretKey);
  }

  /** Verify an Ed25519 signature against a public key */
  verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    return crypto.verify(data, signature, publicKey);
  }

  /** Get the data directory path */
  getDataDir(): string {
    return this.dataDir;
  }

  private defaultDataDir(): string {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    return `${home}/.opena2a/aim-core`;
  }
}
