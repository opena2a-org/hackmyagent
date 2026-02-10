/** Options for creating an AIMCore instance */
export interface AIMCoreOptions {
  /** Human-readable agent name */
  agentName: string;
  /** Directory for identity keys, audit log, and config. Defaults to ~/.opena2a/aim-core */
  dataDir?: string;
  /** Optional AIM server URL for fleet reporting */
  serverUrl?: string;
}

/** Ed25519 identity for an agent */
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

/** Stored identity (includes secret key — never exported via getIdentity) */
export interface StoredIdentity extends AIMIdentity {
  /** Ed25519 secret key (base64) — 64 bytes: 32 private + 32 public */
  secretKey: string;
}

/** A single audit event */
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

/** Input for logging an event (timestamp is added automatically) */
export type AuditEventInput = Omit<AuditEvent, 'timestamp'>;

/** Options for reading audit events */
export interface AuditReadOptions {
  /** Maximum number of events to return */
  limit?: number;
  /** Only return events after this ISO timestamp */
  since?: string;
}

/** Capability policy loaded from YAML */
export interface CapabilityPolicy {
  /** Policy version */
  version: string;
  /** Default action when no rule matches */
  defaultAction: 'allow' | 'deny';
  /** Capability rules (evaluated in order, first match wins) */
  rules: CapabilityRule[];
}

/** A single capability rule */
export interface CapabilityRule {
  /** Capability pattern (e.g., "db:read", "net:*", "fs:write:/tmp/*") */
  capability: string;
  /** Action for this rule */
  action: 'allow' | 'deny';
  /** Optional: restrict to specific plugins */
  plugins?: string[];
}

/** Trust score result */
export interface TrustScore {
  /** Overall trust score (0-1) */
  overall: number;
  /** Individual factor scores */
  factors: TrustFactors;
  /** ISO timestamp of calculation */
  calculatedAt: string;
}

/** Individual trust factor scores (each 0-1) */
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

/** Hints provided by plugins to inform trust calculation */
export interface TrustHints {
  // Core factors (mapped to trust score weights)
  secretsManaged?: boolean;
  configSigned?: boolean;
  skillsVerified?: boolean;
  networkControlled?: boolean;
  heartbeatMonitored?: boolean;

  // Extended plugin signals (8-plugin coverage)
  sessionsProtected?: boolean;
  promptsGuarded?: boolean;
  daemonHardened?: boolean;
  dlpEnabled?: boolean;
  runtimeProtected?: boolean;
}
