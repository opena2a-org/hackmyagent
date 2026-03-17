/**
 * Attack Mode Types
 * Adversarial security testing for AI agents
 */

export type AttackCategory =
  | 'prompt-injection'       // PI - Manipulate agent behavior via input
  | 'jailbreak'              // JB - Bypass safety guardrails
  | 'data-exfiltration'      // DE - Extract sensitive information
  | 'capability-abuse'       // CA - Misuse agent tools/capabilities
  | 'context-manipulation'   // CM - Poison context/memory
  | 'mcp-exploitation'       // MCP - Exploit MCP tool parameters
  | 'a2a-attack'             // A2A - Exploit agent-to-agent messaging
  | 'memory-weaponization'   // MEM - Weaponize agent memory systems
  | 'context-window'         // CTX - Manipulate context window attention
  | 'supply-chain'           // SUP - Attack agent dependency supply chain
  | 'tool-shadow';           // SHADOW - Shadow/replace agent tools

export type AttackIntensity =
  | 'passive'     // Observation only, minimal risk
  | 'active'      // Standard attack payloads
  | 'aggressive'; // Creative/risky payloads

export type AttackSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AttackPayload {
  /** Unique identifier (e.g., PI-001) */
  id: string;
  /** Attack category */
  category: AttackCategory;
  /** Human-readable name */
  name: string;
  /** What this payload tests */
  description: string;
  /** Minimum intensity level to include this payload */
  intensity: AttackIntensity;
  /** The actual attack payload/prompt */
  payload: string;
  /** Regex patterns indicating successful attack */
  successIndicators: RegExp[];
  /** Regex patterns indicating attack was blocked */
  blockedIndicators: RegExp[];
  /** Severity if attack succeeds */
  severity: AttackSeverity;
  /** OASB-1 control this tests */
  oasbControl?: string;
  /** CWE reference if applicable */
  cwe?: string;
  /** Remediation guidance */
  remediation: string;
}

export interface AttackResult {
  /** Payload that was tested */
  payload: AttackPayload;
  /** Target that was tested */
  target: string;
  /** Whether the attack succeeded */
  success: boolean;
  /** Whether the attack was explicitly blocked */
  blocked: boolean;
  /** Confidence in the result (0-1) */
  confidence: number;
  /** Evidence of success/failure */
  evidence: string;
  /** Raw response from target (truncated) */
  response?: string;
  /** Time taken in ms */
  duration: number;
  /** Timestamp */
  timestamp: Date;
}

export interface AttackReport {
  /** Target that was tested */
  target: string;
  /** Target type */
  targetType: 'api' | 'mcp' | 'a2a' | 'local';
  /** Attack intensity used */
  intensity: AttackIntensity;
  /** Categories tested */
  categories: AttackCategory[];
  /** Start time */
  startTime: Date;
  /** End time */
  endTime: Date;
  /** Total duration in ms */
  duration: number;
  /** Summary statistics */
  summary: {
    total: number;
    successful: number;
    blocked: number;
    inconclusive: number;
    bySeverity: Record<AttackSeverity, number>;
    byCategory: Record<AttackCategory, { total: number; successful: number }>;
  };
  /** Individual results */
  results: AttackResult[];
  /** Overall risk score (0-100) */
  riskScore: number;
  /** Overall risk rating */
  riskRating: 'critical' | 'high' | 'medium' | 'low' | 'secure';
}

export interface AttackTarget {
  /** Target URL or identifier */
  url: string;
  /** Target type */
  type: 'api' | 'mcp' | 'a2a' | 'local';
  /** Local directory path (for --local mode scanning) */
  localPath?: string;
  /** Authentication headers */
  headers?: Record<string, string>;
  /** API format */
  apiFormat?: 'openai' | 'anthropic' | 'mcp-jsonrpc' | 'a2a' | 'custom';
  /** Model to test (for API targets) */
  model?: string;
  /** System prompt (for local testing) */
  systemPrompt?: string;
  /** MCP tool name (for mcp-jsonrpc targets) */
  mcpTool?: string;
  /** A2A sender identity (for a2a targets) */
  a2aSender?: string;
  /** A2A recipient identity (for a2a targets) */
  a2aRecipient?: string;
}

export interface AttackOptions {
  /** Target to attack */
  target: AttackTarget;
  /** Attack intensity */
  intensity: AttackIntensity;
  /** Categories to test (default: all) */
  categories?: AttackCategory[];
  /** Specific payload IDs to run */
  payloadIds?: string[];
  /** Timeout per request in ms */
  timeout?: number;
  /** Delay between requests in ms (rate limiting) */
  delay?: number;
  /** Maximum concurrent requests */
  concurrency?: number;
  /** Stop on first successful attack */
  stopOnSuccess?: boolean;
  /** Verbose output */
  verbose?: boolean;
  /** Custom payloads (from --payload-file) */
  customPayloads?: AttackPayload[];
}

export interface CustomPayloadInput {
  id: string;
  payload: string;
  name?: string;
  description?: string;
  category?: AttackCategory;
  intensity?: AttackIntensity;
  severity?: AttackSeverity;
  successIndicators?: string[];
  blockedIndicators?: string[];
  oasbControl?: string;
  cwe?: string;
  remediation?: string;
}

export interface CustomPayloadFile {
  payloads: CustomPayloadInput[];
}

/** Category metadata */
export const ATTACK_CATEGORIES: Record<AttackCategory, { name: string; description: string; oasbControls: string[] }> = {
  'prompt-injection': {
    name: 'Prompt Injection',
    description: 'Attempts to manipulate agent behavior via malicious input',
    oasbControls: ['3.1', '3.2', '3.3'],
  },
  'jailbreak': {
    name: 'Jailbreaking',
    description: 'Attempts to bypass safety guardrails and restrictions',
    oasbControls: ['3.1', '4.1'],
  },
  'data-exfiltration': {
    name: 'Data Exfiltration',
    description: 'Attempts to extract sensitive information from the agent',
    oasbControls: ['4.3', '5.2', '8.2'],
  },
  'capability-abuse': {
    name: 'Capability Abuse',
    description: 'Attempts to misuse agent tools and capabilities',
    oasbControls: ['2.2', '2.3', '4.2'],
  },
  'context-manipulation': {
    name: 'Context Manipulation',
    description: 'Attempts to poison agent context or memory',
    oasbControls: ['8.1', '8.2'],
  },
  'mcp-exploitation': {
    name: 'MCP Exploitation',
    description: 'Attempts to exploit MCP tool call parameters (path traversal, command injection, SSRF)',
    oasbControls: ['2.2', '2.3'],
  },
  'a2a-attack': {
    name: 'A2A Attack',
    description: 'Attempts to exploit agent-to-agent messaging (identity spoofing, delegation abuse)',
    oasbControls: ['5.1', '5.2'],
  },
  'memory-weaponization': {
    name: 'Memory Weaponization',
    description: 'Attempts to poison, persist, or extract data through agent memory systems',
    oasbControls: ['8.1', '8.2'],
  },
  'context-window': {
    name: 'Context Window',
    description: 'Attempts to manipulate context window attention to displace safety instructions',
    oasbControls: ['3.1', '3.2'],
  },
  'supply-chain': {
    name: 'Supply Chain',
    description: 'Attempts to compromise agent dependencies through supply chain attacks',
    oasbControls: ['6.1', '6.2', '6.3'],
  },
  'tool-shadow': {
    name: 'Tool Shadow',
    description: 'Attempts to shadow, replace, or proxy legitimate tools to intercept data or modify behavior',
    oasbControls: ['2.2', '2.3'],
  },
};
