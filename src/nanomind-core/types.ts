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
   * Where the matched VALUE behind `evidence` sits in the ORIGINAL artifact
   * content: 0-based character offset and length (#368).
   *
   * Present only when the producer matched a concrete substring of the
   * unmodified content and can therefore say exactly where it was — today the
   * canonical credential-format scan, and ONLY on `source_code`, because that
   * is the artifact type the compiler runs it for. Every other artifact type
   * reaches the analyzers with no offset anywhere on this array. Absent too
   * when `evidence` is a label, a rollup, or a match against the preprocessed
   * analysis view, whose offsets do not map back to the file.
   *
   * The alternative an emit site falls back to without this is "find the
   * leftmost credential-SHAPED string in the file", which cites a SHA-256
   * digest or a doc placeholder sitting above the real key. A citation that is
   * confidently wrong is worse than an absent one, so these two fields are how
   * a finding cites the value it actually names — on the artifact types that
   * carry them. Where they are absent the emit site keeps the leftmost-match
   * guess and its wrong-line risk; adding a second producer is what would
   * close that, and no such producer exists yet.
   */
  evidenceOffset?: number;
  /** Length of the matched value at `evidenceOffset`. See above. */
  evidenceLength?: number;
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
