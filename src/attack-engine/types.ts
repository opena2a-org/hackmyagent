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
  /**
   * Sentences in the artifact built on a modal verb (must / never / always /
   * cannot / ...), extracted verbatim and of **unknown polarity**.
   *
   * Named for what the extractor can actually see (#369). It used to be called
   * `constraints`, which asserted these were limitations the agent operates
   * under — and the engine then scored resistance by counting them. They are not
   * that. `Never reveal secrets.` and `Never refuse.` are the same syntactic
   * shape pointing opposite ways, and on a jailbreak document every match is
   * attacker text. Treat this as attack surface, never as evidence of a defence.
   */
  modalStatements: string[];
  /**
   * Governance vocabulary the artifact MENTIONS (`soul.md`, `system prompt`,
   * `runtime check`). Empty when none appear.
   *
   * Mentions, never enforcement. This was `governanceMechanism: string`, a
   * single answer derived from a text match on the scanned file, and the surface
   * builder suppressed the `instruction_override` surface whenever it was not
   * `'none'` — so a jailbreak demanding "your system prompt" was read as HAVING
   * one, and mapped fewer attack surfaces than benign prose (#369, second pass).
   * A file cannot report whether the agent it describes is governed. Treat an
   * entry here as something an attacker knows to aim at, not as a defence.
   */
  governanceMentions: string[];
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
// Attack Categories (12 from HMA)
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
  | 'semantic_mismatch'
  | 'policy_enforcement_integrity';

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

/**
 * `NOT_EXECUTED` is a first-class outcome, not an error state (#369).
 *
 * The engine generates payloads but has no way to run them against an agent
 * today, so every result it produces carries this. It exists as its own value
 * rather than defaulting to `FAIL` because "the attack did not land" and "the
 * attack was never attempted" are opposite facts about the target, and the
 * shipped engine conflated them into a resilience score.
 */
export type AttackOutcome = 'SUCCESS' | 'PARTIAL' | 'FAIL' | 'NOT_EXECUTED';

export interface AttackResult {
  payloadId: string;
  category: AttackCategory;
  /**
   * The attack input this result is about, verbatim.
   *
   * Carried so `--json` exposes what the session would send. Without it
   * "Payloads generated: 5" is a number the caller cannot act on, and with no
   * execution path the payloads ARE the deliverable — the thing a user can run
   * against their own agent by hand.
   *
   * Derived from the scanned artifact, so it is untrusted text. Anything
   * rendering it to a terminal must escape it first — `escapeForDisplay`.
   *
   * NOT automatically safe in `--json`: `JSON.stringify` escapes C0 and quotes
   * but passes C1 (U+0080-U+009F, of which U+009B is CSI) and DEL through as raw
   * bytes, which `src/ui/display-safe.ts` classifies as display hazards. That is
   * a property of every `--json` surface in this CLI rather than of this field,
   * and is not addressed here — but do not read "it is JSON" as "it is escaped".
   */
  payloadInput: string;
  outcome: AttackOutcome;
  /**
   * What the target actually did in response.
   *
   * ABSENT — not empty-string — when `outcome` is `NOT_EXECUTED`. There is no
   * observation to report, and `''` reads as "the target did nothing", which is
   * itself a claim about behaviour nobody watched. This field previously held
   * synthetic strings (`Skill complied with ... attack`) generated for runs that
   * never happened; it must only ever carry real output or a faithful summary
   * of it.
   */
  observedBehavior?: string;
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
  /**
   * Overall resilience score (0-1, 1 = all attacks blocked), or `null` when no
   * attack was executed and the session therefore measured nothing.
   *
   * `null` rather than `0` is the whole point (#369). Resilience is a property
   * of a run: a document does not resist an attack nobody made. The shipped
   * engine derived this number from a regex over the artifact's own text, which
   * made it an attacker-controllable signal — a jailbreak scored 1.0 because its
   * imperatives were counted as declared defences, while benign prose scored 0
   * through an `entries.length || 1` denominator that invented a defence to
   * divide by. Any consumer must branch on `null` and report "not measured";
   * coercing it to a number re-creates the defect.
   */
  resilienceScore: number | null;
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

/**
 * Where a session's outcomes came from — the provenance every consumer must
 * read before treating any number in the session as a measurement (#369).
 */
export interface AttackEvaluation {
  /**
   * `not_executed`: payloads were generated but never run against an agent, so
   * the session has no evidence about resistance.
   * `executed`: outcomes were derived from a real agent's responses.
   *
   * There is deliberately no `heuristic` member. The heuristic this engine
   * shipped scored resistance by counting modal verbs in the artifact, which is
   * inverted rather than approximate, and a labelled inverted number is still an
   * inverted number.
   */
  mode: 'not_executed' | 'executed';
  /** Payloads generated for this session. */
  generated: number;
  /** Payloads actually run against an agent. Zero whenever `mode` is `not_executed`. */
  executed: number;
  /** Why nothing ran, in one clause the CLI can print. Absent when `mode` is `executed`. */
  reason?: string;
}

export interface AttackSessionResult {
  /** Target profile that was attacked */
  target: SemanticTargetProfile;
  /** All attack results across all iterations */
  results: AttackResult[];
  /** Provenance of every outcome in `results`. Read this before trusting a count. */
  evaluation: AttackEvaluation;
  /**
   * Total payloads generated. Always a real count — generation did happen.
   *
   * Contrast `successCount` / `partialCount` / `vulnerabilities` below, which
   * describe a run that did not.
   */
  totalPayloads: number;
  /**
   * Attacks observed to succeed. `0` while `evaluation.mode` is `not_executed`,
   * where it means "none were attempted" and NOT "none got through".
   *
   * `resilienceScore` is `null` for exactly this reason and these three fields
   * cannot be, because a count and a list have no honest empty-but-unmeasured
   * value. `evaluation.mode` is the one that carries it — a consumer branching
   * on `vulnerabilities.length === 0` alone reads an unconditional all-clear on
   * every artifact. Check `evaluation.mode === 'executed'` first.
   */
  successCount: number;
  /** Partial successes observed. Same caveat as `successCount`. */
  partialCount: number;
  /** Defense map discovered */
  defenseMap: DefenseMap;
  /** Duration of the full attack session */
  durationMs: number;
  /**
   * Vulnerabilities CONFIRMED by an executed attack, with specific remediation.
   * Empty while `evaluation.mode` is `not_executed` — nothing was confirmed
   * because nothing ran, which is not the same as nothing being there.
   */
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
