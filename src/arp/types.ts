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
  classifiedBy: 'L0-rules' | 'L1-statistical' | 'L2-llm';
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
