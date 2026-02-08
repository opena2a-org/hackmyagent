export const VERSION = '0.1.0';

// --- Types ---

export interface AIMCoreOptions {
  /** Human-readable agent name */
  agentName: string;
  /** Directory for identity keys, audit log, and config. Defaults to ~/.opena2a/aim-core */
  dataDir?: string;
  /** Optional AIM server URL for fleet reporting */
  serverUrl?: string;
}

export interface AIMIdentity {
  /** Agent's unique identifier (derived from public key) */
  agentId: string;
  /** Ed25519 public key (base64) */
  publicKey: string;
  /** Agent name from config */
  agentName: string;
  /** ISO timestamp of identity creation */
  createdAt: string;
}

export interface AuditEvent {
  /** ISO timestamp */
  timestamp: string;
  /** Plugin that generated the event */
  plugin: string;
  /** Action performed */
  action: string;
  /** Target resource */
  target: string;
  /** Result: allowed, denied, error */
  result: 'allowed' | 'denied' | 'error';
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

export interface CapabilityPolicy {
  /** Policy version */
  version: string;
  /** Default action when no rule matches */
  defaultAction: 'allow' | 'deny';
  /** Capability rules */
  rules: CapabilityRule[];
}

export interface CapabilityRule {
  /** Capability pattern (e.g., "db:read", "net:*", "fs:write:/tmp/*") */
  capability: string;
  /** Action for this rule */
  action: 'allow' | 'deny';
  /** Optional: restrict to specific plugins */
  plugins?: string[];
}

export interface TrustScore {
  /** Overall trust score (0-1) */
  overall: number;
  /** Individual factor scores */
  factors: TrustFactors;
  /** ISO timestamp of calculation */
  calculatedAt: string;
}

export interface TrustFactors {
  /** Identity verified (Ed25519 key exists and is valid) */
  identity: number;
  /** Capabilities declared and enforced */
  capabilities: number;
  /** Audit logging active */
  auditLog: number;
  /** Secrets managed (not hardcoded) */
  secretsManaged: number;
  /** Configuration signed */
  configSigned: number;
  /** Skills integrity verified */
  skillsVerified: number;
  /** Network access controlled */
  networkControlled: number;
  /** Heartbeat monitoring active */
  heartbeatMonitored: number;
}

// --- Core Class ---

export class AIMCore {
  private readonly options: Required<AIMCoreOptions>;

  constructor(options: AIMCoreOptions) {
    this.options = {
      agentName: options.agentName,
      dataDir: options.dataDir ?? this.defaultDataDir(),
      serverUrl: options.serverUrl ?? '',
    };
  }

  /** Get or create the agent's Ed25519 identity */
  async getIdentity(): Promise<AIMIdentity> {
    // TODO: Implement — generate or load Ed25519 keypair from dataDir
    throw new Error('Not implemented');
  }

  /** Check if a capability is allowed by the current policy */
  checkCapability(capability: string, plugin?: string): boolean {
    // TODO: Implement — load policy from dataDir, evaluate rules
    throw new Error('Not implemented');
  }

  /** Load capability policy from YAML file */
  async loadPolicy(): Promise<CapabilityPolicy> {
    // TODO: Implement — parse YAML from dataDir/policy.yaml
    throw new Error('Not implemented');
  }

  /** Log an audit event to the local JSON-lines file */
  async logEvent(event: Omit<AuditEvent, 'timestamp'>): Promise<void> {
    // TODO: Implement — append to dataDir/audit.jsonl
    throw new Error('Not implemented');
  }

  /** Read audit events from local log */
  async readAuditLog(options?: { limit?: number; since?: string }): Promise<AuditEvent[]> {
    // TODO: Implement — read from dataDir/audit.jsonl
    throw new Error('Not implemented');
  }

  /** Calculate the agent's trust score based on current state */
  async calculateTrust(): Promise<TrustScore> {
    // TODO: Implement — evaluate 8 trust factors
    throw new Error('Not implemented');
  }

  /** Sign data with the agent's Ed25519 private key */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    // TODO: Implement — sign with tweetnacl
    throw new Error('Not implemented');
  }

  /** Verify a signature against a public key */
  async verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // TODO: Implement — verify with tweetnacl
    throw new Error('Not implemented');
  }

  /** Connect to an AIM server for fleet reporting (optional) */
  async connectServer(serverUrl: string): Promise<void> {
    // TODO: Implement — register with AIM server, begin periodic reporting
    throw new Error('Not implemented');
  }

  private defaultDataDir(): string {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    return `${home}/.opena2a/aim-core`;
  }
}
