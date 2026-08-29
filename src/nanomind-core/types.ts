/**
 * NanoMind Core Types -- Abstract Security Tree (AST)
 *
 * The SecurityAST is the foundational data structure that ALL scanners consume.
 * NanoMind compiles raw artifacts into ASTs. Analyzers query ASTs, not raw text.
 *
 * Security properties:
 * - Every AST is cryptographically signed (Ed25519)
 * - Signature includes contentHash + modelVersion + timestamp
 * - Analyzers verify signature before processing
 * - Tampered ASTs are rejected
 */

// ============================================================================
// Abstract Security Tree
// ============================================================================

export interface SecurityAST {
  /** Artifact identity */
  artifactType: ArtifactType;
  contentHash: string;            // SHA-256 of the original artifact
  artifactPath?: string;          // File path (relative)
  artifactSize: number;           // Bytes

  /** Declarations: what the artifact SAYS it does */
  declaredPurpose: string;
  declaredCapabilities: Capability[];
  declaredConstraints: Constraint[];
  declaredDataAccess: DataAccessPattern[];

  /** Inferred: what NanoMind UNDERSTANDS it does */
  inferredCapabilities: Capability[];
  inferredRiskSurface: RiskSurface[];
  intentClassification: IntentClass;
  intentConfidence: number;       // 0-1

  /** Relationships */
  dependsOn: string[];            // Content hashes of referenced artifacts
  governedBy: string[];           // Content hashes of governing artifacts (SOUL, system prompt)

  /** Evidence: exact text regions supporting the classification */
  evidenceSpans: EvidenceSpan[];

  /** Cryptographic integrity */
  signature: string;              // Ed25519 signature of the AST (excluding this field)
  modelVersion: string;           // NanoMind version that produced this AST
  compiledAt: string;             // ISO 8601 timestamp
}

// ============================================================================
// Artifact Types
// ============================================================================

export type ArtifactType =
  | 'skill'
  | 'mcp_config'
  | 'soul'
  | 'system_prompt'
  | 'agent_config'
  | 'a2a_card'
  | 'credential_file'
  | 'source_code'
  | 'env_file'
  | 'unknown';

// ============================================================================
// Capabilities
// ============================================================================

export interface Capability {
  /** Capability identifier (e.g., "db.read", "api.call", "file.write") */
  name: string;
  /** Scope of the capability (e.g., "customers table", "weather API") */
  scope: string;
  /** Was this explicitly declared in the artifact? */
  declared: boolean;
  /** Was this inferred by NanoMind from the content? */
  inferred: boolean;
  /** Risk level of this capability */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  /** Evidence: text span that declares or implies this capability */
  evidence?: string;
}

// ============================================================================
// Constraints
// ============================================================================

export interface Constraint {
  /** The constraint as written in the artifact */
  text: string;
  /** Governance domain (trust, oversight, data_handling, etc.) */
  domain: ConstraintDomain;
  /** How enforceable is this constraint? (0 = aspirational, 1 = enforced) */
  enforceability: number;
  /** How easy to bypass? (0 = robust, 1 = trivially bypassable) */
  bypassRisk: number;
  /** Specific weakness if bypassRisk > 0.5 */
  weakness?: string;
}

export type ConstraintDomain =
  | 'trust_hierarchy'
  | 'human_oversight'
  | 'data_handling'
  | 'action_reversibility'
  | 'capability_boundary'
  | 'identity_disclosure'
  | 'error_handling'
  | 'credential_management'
  | 'behavioral_constraint'
  | 'general';

// ============================================================================
// Data Access Patterns
// ============================================================================

export interface DataAccessPattern {
  /** What data type is accessed */
  dataType: string;         // "pii", "credentials", "financial", "general"
  /** How it's accessed */
  accessMode: 'read' | 'write' | 'delete' | 'transmit';
  /** Where it goes (if transmit) */
  destination?: string;
  /** Is this access declared in capabilities? */
  coveredByCapability: boolean;
  /** What the compiler matched to produce this pattern, and how it paired it. */
  matched?: DataAccessMatch;
}

/**
 * The tokens behind a data-access pattern, with their offsets in the artifact.
 *
 * `scope` records HOW the compiler paired them. `'document'` is the prose
 * engine: a noun anywhere, a verb anywhere, and a URL co-located with the verb
 * by paragraph — the credential analyzer may still pair a read pattern with a
 * transmit pattern document-wide. `'structured'` is the JSON engine: the noun
 * and the verb were required to share one leaf string value and the URL to
 * sit in that leaf or a sibling, so the pairing is already resolved and the
 * analyzer must not pair document-wide again (hackmyagent #541, #403).
 */
export interface DataAccessMatch {
  scope: 'document' | 'structured';
  /** The credential noun as written. */
  term?: string;
  termOffset?: number;
  /** The transmit verb as written. */
  verb?: string;
  verbOffset?: number;
  /** Offset of `destination` in the artifact, when it was located verbatim. */
  destinationOffset?: number;
}

// ============================================================================
// Risk Surface
// ============================================================================

export interface RiskSurface {
  /** What aspect of the artifact is risky */
  surface: string;
  /** Attack class from HMA taxonomy */
  attackClass: string;
  /** Confidence this is a real risk (0-1) */
  confidence: number;
  /** Specific text that creates this risk */
  evidence: string;
  /**
   * Character offset, in the ORIGINAL artifact content, of the bytes this risk
   * was raised on. Present only where the producer recorded one.
   *
   * `evidence` is not always a substring of the artifact — the canonical
   * credential scan emits a CLASSIFICATION (`OpenAI legacy key: [REDACTED]`)
   * rather than the matched value, deliberately, so no part of a secret rides
   * in a finding. That made the risk unlocatable by search: `extractEvidenceSpans`
   * looks the evidence up with `indexOf` and finds nothing, so the finding
   * built from it carried no line and therefore no `Verify:` (#368). The offset
   * is recorded at the point of the match instead, where it is exact.
   */
  offset?: number;
  /** How to mitigate */
  mitigation?: string;
}

// ============================================================================
// Intent Classification
// ============================================================================

export type IntentClass = 'benign' | 'suspicious' | 'malicious';

// ============================================================================
// Evidence Spans
// ============================================================================

export interface EvidenceSpan {
  /** Start character offset in original artifact */
  start: number;
  /** End character offset */
  end: number;
  /** The actual text */
  text: string;
  /** What this evidence supports */
  supports: string;         // e.g., "exfiltration_intent", "credential_exposure"
  /** Confidence this evidence is relevant */
  confidence: number;
}

// ============================================================================
// Compiler Configuration
// ============================================================================

export interface CompilerConfig {
  /** NanoMind daemon URL */
  daemonUrl: string;
  /** Signing key for AST integrity (Ed25519 private key, hex) */
  signingKey?: string;
  /** Whether to call NanoMind for inference (false = heuristic only) */
  useNanoMind: boolean;
  /** Maximum artifact size to process (bytes, default 1MB) */
  maxArtifactSize: number;
  /** Request timeout for NanoMind daemon (ms) */
  daemonTimeoutMs: number;
}

export const DEFAULT_COMPILER_CONFIG: CompilerConfig = {
  daemonUrl: 'http://127.0.0.1:47200',
  useNanoMind: true,
  maxArtifactSize: 1_048_576, // 1MB
  daemonTimeoutMs: 5000,
};

// ============================================================================
// Compilation Result
// ============================================================================

export interface CompilationResult {
  /** The compiled AST */
  ast: SecurityAST;
  /** Compilation metadata */
  durationMs: number;
  /** Whether NanoMind was used (false = heuristic fallback) */
  nanomindUsed: boolean;
  /** Warnings during compilation */
  warnings: string[];
}
