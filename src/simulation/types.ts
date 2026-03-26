/**
 * Simulation Engine Types
 *
 * The Skill Simulation Engine executes skills inside a controlled LLM
 * and observes behavioral patterns. This is NOT a code sandbox --
 * it observes what an LLM decides to do when running a skill.
 */

// ============================================================================
// Simulation Results
// ============================================================================

export type SimulationVerdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';

export interface SimulationResult {
  verdict: SimulationVerdict;
  confidence: number; // 0.0-1.0
  failedProbes: ProbeResult[];
  passedProbes: ProbeResult[];
  behavioralTrace: MockToolCall[];
  semanticDelta: number; // 0.0-1.0: how far observed behavior diverged from declared purpose
  durationMs: number;
  probeCount: number;
  layer: 1 | 2 | 3;
}

// ============================================================================
// Probes
// ============================================================================

export type ProbeCategory =
  | 'exfiltration'
  | 'override_resistance'
  | 'scope_expansion'
  | 'credential_secret'
  | 'memory_persistence'
  | 'heartbeat_remote'
  | 'semantic_consistency';

export interface ProbeDefinition {
  id: string;
  name: string;
  category: ProbeCategory;
  description: string;
  input: string; // The structured input to inject
  passCondition: string; // Human-readable pass criteria
  failCondition: string; // Human-readable fail criteria
  attackClass: string; // Maps to DVAA/HMA attack taxonomy
  layer: 2 | 3; // Which layer this probe runs in
}

export interface ProbeResult {
  probeId: string;
  probeName: string;
  category: ProbeCategory;
  passed: boolean;
  attackClass: string;
  observedBehavior: string; // What the LLM actually did
  evidence: string[]; // Specific tool calls or responses that triggered the result
  confidence: number;
  durationMs: number;
}

// ============================================================================
// Mock Tool Environment
// ============================================================================

export type MockToolType =
  | 'external_api'
  | 'database'
  | 'memory'
  | 'credential'
  | 'communication';

export interface MockToolCall {
  toolType: MockToolType;
  toolName: string;
  timestamp: number;
  args: Record<string, unknown>;
  response: unknown;
  flagged: boolean; // Whether this call triggered a malicious signal
  flagReason?: string;
}

export interface MockToolConfig {
  type: MockToolType;
  name: string;
  schema: Record<string, string>; // Parameter schema for the mock
  syntheticData?: Record<string, unknown>; // Pre-loaded synthetic data
}

// ============================================================================
// Target Profile
// ============================================================================

export interface SkillProfile {
  name: string;
  declaredPurpose: string;
  capabilities: string[];
  constraints: string[];
  toolPermissions: string[];
  heartbeatURLs: string[];
  dataAccessPatterns: string[];
  governanceMechanism: 'soul' | 'system_prompt' | 'runtime_check' | 'none';
  rawContent: string;
}

// ============================================================================
// Simulation Config
// ============================================================================

export interface SimulationConfig {
  maxProbes: number; // Default: 20 for Layer 3, 5 for Layer 2
  timeoutMs: number; // Default: 30000 for Layer 3, 3000 for Layer 2
  maxIterations: number; // For adaptive feedback loop
  parallelProbes: boolean; // Run independent probes in parallel
  llmProvider: 'nanomind-daemon' | 'anthropic' | 'ollama'; // Which LLM runs the skill
}

export const DEFAULT_LAYER2_CONFIG: SimulationConfig = {
  maxProbes: 5,
  timeoutMs: 3000,
  maxIterations: 1,
  parallelProbes: true,
  llmProvider: 'nanomind-daemon',
};

export const DEFAULT_LAYER3_CONFIG: SimulationConfig = {
  maxProbes: 20,
  timeoutMs: 30000,
  maxIterations: 5,
  parallelProbes: true,
  llmProvider: 'nanomind-daemon',
};
