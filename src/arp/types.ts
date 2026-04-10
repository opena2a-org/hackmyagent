// --- Core ARP Types ---

/** An event emitted by a monitor */
export interface ARPEvent {
  /** Unique event ID */
  id: string;
  /** ISO timestamp */
  timestamp: string;
  /** Monitor that generated the event */
  source: MonitorType;
  /** Event category */
  category: EventCategory;
  /** Severity determined by L0 rules */
  severity: EventSeverity;
  /** Human-readable description */
  description: string;
  /** Structured event data (monitor-specific) */
  data: Record<string, unknown>;
  /** Which intelligence layer classified this event */
  classifiedBy: 'L0-rules' | 'L0-comply' | 'L1-statistical' | 'L2-llm';
  /** LLM assessment (only if classified by L2) */
  llmAssessment?: LLMAssessment;
}

export type MonitorType = 'process' | 'network' | 'filesystem' | 'skill' | 'heartbeat' | 'prompt' | 'mcp-protocol' | 'a2a-protocol';
export type EventCategory = 'normal' | 'anomaly' | 'violation' | 'threat';
export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Result from LLM analysis of a suspicious event */
export interface LLMAssessment {
  /** Is this event consistent with the agent's declared purpose? */
  consistent: boolean;
  /** Confidence score 0-1 */
  confidence: number;
  /** 1-2 sentence reasoning */
  reasoning: string;
  /** Recommended action */
  recommendation: 'allow' | 'alert' | 'pause' | 'kill';
  /** Tokens used for this assessment */
  tokensUsed: number;
  /** Estimated cost in USD */
  estimatedCost: number;
}

// --- Configuration ---

export interface ARPConfig {
  /** Agent name (for logging and LLM context) */
  agentName: string;
  /** Agent's declared purpose / description */
  agentDescription?: string;
  /** Agent's declared capabilities (for LLM context) */
  declaredCapabilities?: string[];
  /** Data directory for logs and state */
  dataDir?: string;
  /** Which monitors to enable (default: all) */
  monitors?: MonitorConfig;
  /** Alert and enforcement rules */
  rules?: AlertRule[];
  /** Intelligence layer configuration */
  intelligence?: IntelligenceConfig;
  /** Application-level interceptors (zero-latency, 100% accuracy) */
  interceptors?: InterceptorConfig;
  /** AI-layer protection (prompt, MCP, A2A scanning) */
  aiLayer?: AILayerConfig;
  /** HTTP reverse proxy configuration */
  proxy?: ProxyConfig;
  /** GTIN (Global Threat Intelligence Network) opt-in configuration */
  gtin?: GTINConfig;
}

export interface GTINConfig {
  /** Whether GTIN telemetry is enabled (default: false, opt-in only) */
  enabled: boolean;
  /** Sensor token override (auto-generated if not provided) */
  sensorToken?: string;
  /** Registry URL override (default: https://api.oa2a.org) */
  registryUrl?: string;
}

export interface MonitorConfig {
  process?: { enabled: boolean; intervalMs?: number };
  network?: { enabled: boolean; intervalMs?: number; allowedHosts?: string[] };
  filesystem?: { enabled: boolean; watchPaths?: string[]; allowedPaths?: string[] };
  skill?: { enabled: boolean };
  heartbeat?: { enabled: boolean; expectedUrl?: string; maxStaleMs?: number };
}

/** Interceptor configuration — application-level hooks for zero-latency detection */
export interface InterceptorConfig {
  /** Hook child_process module for process spawn interception */
  process?: { enabled: boolean };
  /** Hook net.Socket for outbound connection interception */
  network?: { enabled: boolean; allowedHosts?: string[] };
  /** Hook fs module for file operation interception */
  filesystem?: { enabled: boolean; allowedPaths?: string[] };
}

export interface AlertRule {
  /** Rule name */
  name: string;
  /** Trigger condition */
  condition: AlertCondition;
  /** Action to take */
  action: 'log' | 'alert' | 'pause' | 'kill';
  /** Escalate to L2 LLM for confirmation before enforcement? */
  requireLlmConfirmation?: boolean;
}

export interface AlertCondition {
  /** Monitor source to match */
  source?: MonitorType;
  /** Category to match */
  category?: EventCategory;
  /** Minimum severity to trigger */
  minSeverity?: EventSeverity;
  /** Custom field match (e.g., { "data.host": "*.evil.com" }) */
  fieldMatch?: Record<string, string>;
  /** Threshold: trigger after N events in windowMs */
  threshold?: { count: number; windowMs: number };
}

// --- Intelligence Layer (the innovation) ---

export interface IntelligenceConfig {
  /** Enable LLM-assisted analysis (default: true) */
  enabled?: boolean;
  /** LLM adapter to use */
  adapter?: LLMAdapterType;
  /** Custom adapter config (API key, model, etc.) */
  adapterConfig?: Record<string, unknown>;
  /** Monthly budget in USD (default: 5.00) */
  budgetUsd?: number;
  /** Maximum tokens per single assessment (default: 300) */
  maxTokensPerCall?: number;
  /** Maximum L2 calls per hour (default: 20) */
  maxCallsPerHour?: number;
  /** Minimum L1 severity to escalate to L2 */
  minSeverityForLlm?: EventSeverity;
  /** Batch low-priority anomalies instead of individual calls */
  enableBatching?: boolean;
  /** Batch window in ms (default: 300000 = 5 min) */
  batchWindowMs?: number;
}

export type LLMAdapterType =
  | 'anthropic'   // Direct Anthropic API
  | 'openai'      // Direct OpenAI API
  | 'ollama'      // Local Ollama
  | 'agent-proxy' // Tap into the agent's own LLM (parasitic mode)
  | 'custom';     // User-provided adapter

/** Interface that LLM adapters must implement */
export interface LLMAdapter {
  /** Adapter name */
  readonly name: string;
  /** Send a micro-prompt and get a structured response */
  assess(prompt: string, maxTokens: number): Promise<LLMResponse>;
  /** Estimate cost for a given prompt length */
  estimateCost(inputTokens: number, outputTokens: number): number;
  /** Check if the adapter is available and configured */
  healthCheck(): Promise<boolean>;
}

export interface LLMResponse {
  content: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
}

// --- Budget Tracking ---

export interface BudgetState {
  /** Total spent in current period (USD) */
  totalSpentUsd: number;
  /** Period start (ISO timestamp) */
  periodStart: string;
  /** Number of L2 calls made */
  totalCalls: number;
  /** Calls in current hour */
  callsThisHour: number;
  /** Hour start (ISO timestamp) */
  hourStart: string;
  /** Per-call cost history (last 100) */
  recentCosts: Array<{ timestamp: string; cost: number; tokens: number }>;
}

// --- Enforcement ---

export type EnforcementAction = 'log' | 'alert' | 'pause' | 'kill';

export interface EnforcementResult {
  action: EnforcementAction;
  targetPid?: number;
  success: boolean;
  reason: string;
  event: ARPEvent;
}

// --- AI-Layer Configuration ---

export interface AILayerConfig {
  /** Prompt scanning (injection, jailbreak, data leak detection) */
  prompt?: { enabled: boolean };
  /** MCP protocol scanning (parameter injection, path traversal, SSRF) */
  mcp?: { enabled: boolean; allowedTools?: string[] };
  /** A2A protocol scanning (identity spoofing, delegation abuse) */
  a2a?: { enabled: boolean; trustedAgents?: string[] };
}

// --- Proxy Configuration ---

export interface ProxyConfig {
  /** Port to listen on */
  port: number;
  /** Upstream targets */
  upstreams: ProxyUpstream[];
  /** Block requests on detection (default: false, alert only) */
  blockOnDetection?: boolean;
  /**
   * Optional path to a signed capability manifest YAML file. When set, the
   * proxy loads and verifies the manifest at `start()`. On any verification
   * failure the proxy enters a deny-all state and every request is answered
   * with 403. See `src/arp/crypto/manifest-loader.ts` for the wire format.
   */
  manifestPath?: string;
}

/**
 * Structured log emitted when a capability manifest is rejected at proxy
 * start. Passed to `ARPProxyDeps.onManifestRejection` so callers can route
 * the rejection to a SIEM or audit trail. The client that triggered the
 * request never sees these details; it only gets a generic 403 deny reason.
 */
export interface ManifestRejectionLog {
  /** Discrete error code from the loader (e.g. SIGNATURE_INVALID, EXPIRED). */
  code: string;
  /** Absolute or relative path the loader attempted to read, if any. */
  manifestPath?: string;
  /** Short, non-sensitive reason string for the rejection. */
  reason?: string;
  /** ISO timestamp when the rejection was observed. */
  timestamp: string;
}

export interface ProxyUpstream {
  /** Path prefix to route (e.g., '/openai', '/mcp', '/a2a') */
  pathPrefix: string;
  /** Upstream target URL (e.g., 'http://localhost:3003') */
  target: string;
  /** Protocol hint for request/response parsing */
  protocol: 'openai-api' | 'mcp-http' | 'a2a' | 'passthrough';
}

// --- Monitor Interface ---

export interface Monitor {
  readonly type: MonitorType;
  start(): Promise<void>;
  stop(): Promise<void>;
  isRunning(): boolean;
}

// --- Capability Manifest (AIComply P1, brief Section 5.4) ---

/**
 * Capability tier that bounds what ARP is permitted to do on behalf of an agent.
 * Higher tiers imply broader permitted classes and stricter signing requirements.
 * Per AIComply brief Section 5.4 / AC-010 (seven key hierarchies).
 */
export type CapabilityTier = 'minimal' | 'read' | 'execute' | 'mutate' | 'privileged';

/**
 * Action to take when an agent attempts a class listed in `prohibited_classes`
 * or a class outside `permitted_classes`.
 * Maps onto the existing ARP enforcement actions.
 */
export type ComplyOnViolation = 'log' | 'alert' | 'pause' | 'kill' | 'deny';

/**
 * Compliance envelope for a capability manifest.
 * Allow-list and deny-list of classification classes (as produced by NanoMind-Guard)
 * with a violation policy. If a classification is not in `permitted_classes` and
 * not in `prohibited_classes`, the default policy is `deny` (parse-to-deny, CR-001).
 */
export interface ComplyEnvelope {
  /** Classes the agent is explicitly allowed to operate on */
  permitted_classes: string[];
  /** Classes the agent is explicitly forbidden from (takes precedence over permitted) */
  prohibited_classes: string[];
  /** Action on violation (allow/prohibited class, or unknown class under parse-to-deny) */
  on_violation: ComplyOnViolation;
}

/**
 * Capability manifest for an AIComply-governed agent.
 * Must be signed with an Ed25519+ML-DSA-65 hybrid signature before ARP will load it
 * (see `src/arp/crypto/hybrid-signing.ts`). Invalid or missing signatures trigger
 * parse-to-deny via the existing CR-001 code path.
 *
 * Wire format (YAML on disk) carries the fields below as the signed payload, plus a
 * detached `signature` block. The runtime shape (this interface) is what the loader
 * returns after verification.
 */
export interface CapabilityManifest {
  /** Manifest format version (semver). Current supported: "1.0.0". */
  version: string;
  /** Stable identifier for the governed agent (matches ARPConfig.agentName). */
  agentId: string;
  /** Capability tier for this agent. */
  tier: CapabilityTier;
  /** Compliance envelope (permitted/prohibited classes, violation policy). */
  comply: ComplyEnvelope;
  /** ISO timestamp when the manifest was issued. */
  issuedAt: string;
  /** Optional ISO timestamp when the manifest expires. */
  expiresAt?: string;
  /** Base64-encoded Ed25519 public key used to co-sign the manifest. */
  ed25519PublicKey: string;
  /** Base64-encoded ML-DSA-65 public key used to co-sign the manifest. */
  mldsa65PublicKey: string;
}
