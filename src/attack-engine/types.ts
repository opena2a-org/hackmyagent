/**
 * HMA Adaptive Attack Engine Types
 *
 * NanoMind-powered red team agent that generates target-specific
 * attack payloads, observes responses, adapts, and iterates.
 */

// ============================================================================
// Target Profile
// ============================================================================

export interface SemanticTargetProfile {
  /** Artifact type being targeted */
  artifactType: 'skill' | 'soul' | 'mcp_tool' | 'mcp_server' | 'system_prompt' | 'a2a_card';
  /** What the target claims to do */
  declaredPurpose: string;
  /** Tools and resources the target can access */
  capabilities: string[];
  /** How the target phrases its limitations */
  constraints: string[];
  /** How governance is enforced */
  governanceMechanism: string;
  /** Data types the target regularly touches */
  dataAccessPatterns: string[];
  /** Specific vulnerability surface identified by NanoMind */
  vulnerabilitySurface: VulnerabilitySurfaceEntry[];
}

export interface VulnerabilitySurfaceEntry {
  /** Which aspect of the target is vulnerable */
  surface: string;
  /** How the vulnerability could be exploited */
  exploitApproach: string;
  /** Which attack category this maps to */
  attackCategory: AttackCategory;
  /** Estimated likelihood of success (0-1) */
  estimatedSuccess: number;
}

// ============================================================================
// Attack Categories (11 from HMA)
// ============================================================================

export type AttackCategory =
  | 'prompt_injection'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'social_engineering'
  | 'instruction_override'
  | 'memory_poisoning'
  | 'soul_bypass'
  | 'indirect_injection'
  | 'capability_abuse'
  | 'persistence'
  | 'semantic_mismatch';

// ============================================================================
// Attack Payloads
// ============================================================================

export interface AdaptivePayload {
  id: string;
  category: AttackCategory;
  /** The actual attack input to inject */
  input: string;
  /** Why this payload was generated for this specific target */
  rationale: string;
  /** Which vulnerability surface entry this targets */
  targetsSurface: string;
  /** Iteration number (1 = first attempt) */
  iteration: number;
  /** If iteration > 1, what defense was detected and how this variant adapts */
  adaptsTo?: string;
}

// ============================================================================
// Attack Results
// ============================================================================

export type AttackOutcome = 'SUCCESS' | 'PARTIAL' | 'FAIL';

export interface AttackResult {
  payloadId: string;
  category: AttackCategory;
  outcome: AttackOutcome;
  /** What the target actually did in response */
  observedBehavior: string;
  /** Defense mechanism detected (if FAIL) */
  defenseMechanism?: string;
  /** How strong the defense is (0-1) */
  defenseStrength?: number;
  /** Tool calls observed during the attack */
  toolCalls: Array<{ tool: string; args: Record<string, unknown> }>;
  /** Confidence in the outcome classification */
  confidence: number;
}

// ============================================================================
// Defense Map
// ============================================================================

export interface DefenseMap {
  /** All defenses discovered during the attack session */
  defenses: DefenseEntry[];
  /** Overall resilience score (0-1, 1 = all attacks blocked) */
  resilienceScore: number;
  /** Categories where defenses held */
  strongCategories: AttackCategory[];
  /** Categories where defenses failed */
  weakCategories: AttackCategory[];
}

export interface DefenseEntry {
  mechanism: string;
  category: AttackCategory;
  strength: number; // 0-1
  bypassAttempts: number;
  bypassSuccesses: number;
  /** What the target did to enforce this defense */
  enforcement: string;
}

// ============================================================================
// Session Results
// ============================================================================

export interface AttackSessionResult {
  /** Target profile that was attacked */
  target: SemanticTargetProfile;
  /** All attack results across all iterations */
  results: AttackResult[];
  /** Total payloads generated */
  totalPayloads: number;
  /** Total successful attacks */
  successCount: number;
  /** Total partial successes */
  partialCount: number;
  /** Defense map discovered */
  defenseMap: DefenseMap;
  /** Duration of the full attack session */
  durationMs: number;
  /** Vulnerabilities found with specific remediation */
  vulnerabilities: VulnerabilityFinding[];
}

export interface VulnerabilityFinding {
  category: AttackCategory;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  /** The exact attack input that triggered it */
  triggerInput: string;
  /** What defense was bypassed */
  defenseBypass: string;
  /** Specific fix (not generic) */
  remediation: string;
  /** Confidence based on reproduction count */
  confidence: number;
  /** How many attack iterations confirmed this */
  reproductions: number;
}

// ============================================================================
// Config
// ============================================================================

export interface AttackEngineConfig {
  /** Max iterations per attack category (default: 5) */
  maxIterations: number;
  /** Max total payloads per session (default: 50) */
  maxPayloads: number;
  /** Timeout per individual attack in ms (default: 5000) */
  attackTimeoutMs: number;
  /** Which attack categories to run (default: all 11) */
  categories: AttackCategory[];
  /** LLM provider for payload generation */
  llmProvider: 'nanomind-daemon' | 'anthropic' | 'ollama';
}

export const DEFAULT_ATTACK_CONFIG: AttackEngineConfig = {
  maxIterations: 5,
  maxPayloads: 50,
  attackTimeoutMs: 5000,
  categories: [
    'prompt_injection', 'data_exfiltration', 'privilege_escalation',
    'social_engineering', 'instruction_override', 'memory_poisoning',
    'soul_bypass', 'indirect_injection', 'capability_abuse',
    'persistence', 'semantic_mismatch',
  ],
  llmProvider: 'nanomind-daemon',
};
