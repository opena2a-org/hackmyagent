/**
 * NanoMind Defense-in-Depth
 *
 * Core security principle: NanoMind is ADVISORY, never AUTHORITATIVE.
 * Even a fully compromised NanoMind gains the attacker nothing.
 *
 * Rules:
 * 1. NanoMind can UPGRADE findings (add, increase severity) but NEVER SUPPRESS
 * 2. Static checks always run regardless of NanoMind's opinion
 * 3. Simulation validates independently -- two systems must agree
 * 4. NanoMind has zero access to credentials, secrets, or sensitive data
 * 5. NanoMind daemon is sandboxed: localhost only, no filesystem beyond model
 * 6. AST signatures verified at every consumer
 * 7. Training data provenance tracked and Claude-reviewed
 * 8. A finding from static analysis can never be removed by NanoMind
 */

import type { SecurityAST, IntentClass } from '../types.js';
import type { ShapeId } from '../../types/credential-format.js';

// ============================================================================
// Rule 1: NanoMind can UPGRADE but NEVER SUPPRESS
// ============================================================================

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Enforce that NanoMind can only upgrade severity, never downgrade.
 * If static analysis says HIGH, NanoMind can upgrade to CRITICAL
 * but can NEVER downgrade to LOW or suppress the finding.
 *
 * This means even if NanoMind is compromised and always returns "benign",
 * static findings are never suppressed.
 */
export function enforceSeverityFloor(
  staticSeverity: SeverityLevel,
  nanomindSeverity: SeverityLevel,
): SeverityLevel {
  const staticRank = SEVERITY_ORDER[staticSeverity];
  const nmRank = SEVERITY_ORDER[nanomindSeverity];

  // NanoMind can only make it MORE severe, never less
  return nmRank >= staticRank ? nanomindSeverity : staticSeverity;
}

/**
 * Validate that a NanoMind enhancement never suppresses a static finding.
 * Returns true if the enhancement is valid (doesn't suppress).
 */
export function validateEnhancement(
  staticFindingPassed: boolean,
  nanomindSaysPassed: boolean,
): boolean {
  // Static said FAIL → NanoMind cannot change it to PASS
  if (!staticFindingPassed && nanomindSaysPassed) {
    return false; // BLOCKED: suppression attempt
  }
  return true;
}

// ============================================================================
// Rule 3: Two-System Agreement for Benign Classification
// ============================================================================

/**
 * Require agreement between NanoMind and at least one other system
 * before classifying an artifact as definitively benign.
 *
 * NanoMind alone saying "benign" is not sufficient.
 * Static checks must also show zero findings.
 */
export function requireBenignConsensus(
  nanomindIntent: IntentClass,
  staticFindingCount: number,
  simulationVerdict?: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS',
): {
  finalClassification: IntentClass;
  consensusReached: boolean;
  reason: string;
} {
  // If static found issues, NanoMind's "benign" is overruled
  if (nanomindIntent === 'benign' && staticFindingCount > 0) {
    return {
      finalClassification: 'suspicious',
      consensusReached: false,
      reason: `NanoMind says benign but ${staticFindingCount} static finding(s) exist. Static findings cannot be suppressed.`,
    };
  }

  // If NanoMind says malicious, trust it (it can only upgrade)
  if (nanomindIntent === 'malicious') {
    return {
      finalClassification: 'malicious',
      consensusReached: true,
      reason: 'NanoMind classified as malicious. Malicious classifications are always trusted (can only upgrade).',
    };
  }

  // If simulation ran and disagrees with NanoMind
  if (simulationVerdict === 'MALICIOUS' && nanomindIntent === 'benign') {
    return {
      finalClassification: 'malicious',
      consensusReached: false,
      reason: 'Simulation observed malicious behavior. NanoMind benign classification overruled by behavioral evidence.',
    };
  }

  // Consensus: NanoMind benign + zero static findings + simulation clean (or not run)
  if (nanomindIntent === 'benign' && staticFindingCount === 0) {
    const simClean = !simulationVerdict || simulationVerdict === 'CLEAN';
    return {
      finalClassification: 'benign',
      consensusReached: simClean,
      reason: simClean
        ? 'Consensus: NanoMind benign + zero static findings + simulation clean.'
        : 'NanoMind benign + zero static findings, but simulation not yet run.',
    };
  }

  // Default: suspicious when no consensus
  return {
    finalClassification: 'suspicious',
    consensusReached: false,
    reason: 'No consensus reached. Treated as suspicious until verified.',
  };
}

// ============================================================================
// Rule 4: NanoMind Has Zero Access to Secrets
// ============================================================================

/**
 * One redaction rule: the pattern, what replaces it, and — the reason this
 * table exists — WHICH registry shape a match proves.
 *
 * `redactedShapes` (C9) may carry only ids the redactor resolved FROM THE
 * VALUE, and a marker cannot supply that: `CREDENTIAL_REDACTION_MARKERS` is
 * many-to-one (all five GitHub shapes share `[REDACTED_GITHUB_TOKEN]`), so
 * recovering ids from redacted text would publish five candidates where one
 * matched. The RULES are 1:1 with shape ids, so the id is recorded where it is
 * actually known — at the match — rather than reconstructed afterwards.
 *
 * `replacement` rather than a bare marker because the AWS-secret rule preserves
 * its name anchor via `$1`.
 */
interface CredentialRedactionRule {
  readonly id: ShapeId;
  readonly pattern: RegExp;
  readonly replacement: string;
}

/**
 * The rules, in the order they must run. Order and pattern bodies are carried
 * over verbatim from the sequential `.replace()` chain this table replaced;
 * `redaction-rule-table-parity.test.ts` pins that the folded output is
 * byte-identical to the chain's on every fixture, so the table is a
 * refactoring and not a behaviour change.
 *
 * Two registry shapes are deliberately ABSENT and must stay absent in this
 * release: `entropy-blob` and `jwt`. Adding `entropy-blob` is the measured S4
 * stop condition — its class `[A-Za-z0-9+=_]{40,}` swallows a git SHA-40, a
 * SHA-256 `contentHash`, an npm `sha512-` integrity value and a base64 data-URI
 * body, and HMA's own reports carry `contentHash` values. Closing those two is
 * GAP-8, which is held out of this release deliberately.
 */
const CREDENTIAL_REDACTION_RULES: readonly CredentialRedactionRule[] = [
  // Order matters here in a way it does not in the detector: `sk-proj-` and
  // `sk-ant-api` must be replaced BEFORE the generic `sk-` rule, or a project
  // key would be reported under the legacy label. The legacy rule's
  // alphanumeric-only class already excludes both, and the ordering makes that
  // independent of the class staying that way.
  { id: 'anthropic-key', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, replacement: '[REDACTED_ANTHROPIC_KEY]' },
  { id: 'openai-project-key', pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'openai-key', pattern: /sk-[a-zA-Z0-9]{48,}/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'aws-access-key-id', pattern: /AKIA[0-9A-Z]{16}/g, replacement: '[REDACTED_AWS_KEY]' },
  { id: 'github-pat', pattern: /ghp_[a-zA-Z0-9]{36}/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'github-oauth', pattern: /gho_[a-zA-Z0-9]{36}/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'github-server', pattern: /ghs_[a-zA-Z0-9]{36}/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'github-user', pattern: /ghu_[a-zA-Z0-9]{36}/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'github-fine-grained', pattern: /github_pat_[a-zA-Z0-9_]{60,}/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'gitlab-pat', pattern: /glpat-[a-zA-Z0-9_-]{20,}/g, replacement: '[REDACTED_GITLAB_TOKEN]' },
  { id: 'huggingface-token', pattern: /hf_[a-zA-Z0-9]{34,}/g, replacement: '[REDACTED_HUGGINGFACE_TOKEN]' },
  { id: 'npm-token', pattern: /npm_[a-zA-Z0-9]{36}/g, replacement: '[REDACTED_NPM_TOKEN]' },
  { id: 'stripe-live', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, replacement: '[REDACTED_STRIPE_KEY]' },
  { id: 'stripe-test', pattern: /sk_test_[0-9a-zA-Z]{24,}/g, replacement: '[REDACTED_STRIPE_KEY]' },
  { id: 'sendgrid-key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, replacement: '[REDACTED_SENDGRID_KEY]' },
  { id: 'google-api-key', pattern: /AIza[0-9A-Za-z_-]{35}/g, replacement: '[REDACTED_GOOGLE_KEY]' },
  { id: 'slack-token', pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/g, replacement: '[REDACTED_SLACK_TOKEN]' },
  // AWS secret access key. The name anchor MIRRORS the detector's deliberately,
  // and the value class is intentionally WIDER than the detector's (`=`
  // padding, `{40,}` rather than exactly 40): over-redaction here costs a
  // mangled token, under-redaction leaks a live secret. `$1` preserves the
  // matched name anchor so only the value is removed.
  {
    id: 'aws-secret-access-key',
    pattern: /((?:aws.{0,16}?(?:secret|private).{0,16}?key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*["']?)([A-Za-z0-9/+=]{40,})/gi,
    replacement: '$1[REDACTED_AWS_SECRET]',
  },
  // Two shapes, one rule. A complete block — header through the next footer,
  // never crossing another `-----BEGIN … KEY-----` header — is replaced whole
  // at ANY size: a size bound fails open (an indented RSA-32768 block and
  // FrodoKEM blocks pass
  // 32 KiB, and indentation depth is unbounded), and this rule must fail
  // closed. A header with no footer is replaced together with the key
  // material that follows it and nothing else: base64 runs of 40+, shorter
  // runs that end a line, and RFC 1421 Proc-Type/DEK-Info lines. A header
  // mentioned in prose stays verbatim — a header-to-end-of-line rule was
  // measured to destroy the doc-context words the credential analyzer reads
  // (declared-purpose-redaction.test.ts). The line loop is counted at 16384
  // only to bound the regexp backtrack stack; at 64+ columns that is past the
  // 1 MiB gate, so no real block reaches it.
  { id: 'pem-private-key', pattern: /-----BEGIN [A-Z ]+ KEY-----(?:(?:(?!-----BEGIN [A-Z ]+ KEY-----)[\s\S])*?-----END [A-Z ]+ KEY-----|(?:(?:\s|\\[rn])*(?:[A-Za-z0-9+/=]{40,}|[A-Za-z0-9+/=]+(?=[ \t]*(?:\r?\n|(?:\\r)?\\n|$))|(?:Proc-Type|DEK-Info):[^\r\n\\]*)){1,16384})/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { id: 'connection-string', pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, replacement: '[REDACTED_CONNECTION_STRING]' },
];

/**
 * Upper bound, in bytes, on the content the rules above will be run against.
 *
 * Most of those patterns end in an unbounded lower-bound quantifier over a
 * single character class — `{20,}`, `{48,}`, `{24,}`, `{10,}`, `{34,}`, `{60,}`,
 * and the AWS rule's `[A-Za-z0-9/+=]{40,}`. Against an unbroken same-alphabet
 * run they do not merely get slow: `String.prototype.replace` exhausts V8's
 * backtrack stack and throws `RangeError: Maximum call stack size exceeded`
 * somewhere past 5 MB. Since this table is folded in a loop, the first rule to
 * throw takes the whole redaction pass with it and the error propagates to
 * whatever was being redacted — which is how a multi-megabyte single line
 * reached `SemanticCompiler.compile()` callers as an uncaught `RangeError`
 * through `extractDeclaredPurpose`.
 *
 * Matches `MAX_CREDENTIAL_SCAN_BYTES` in `compiler/semantic-compiler.ts` and
 * `MAX_FILE_SIZE` in `scanner-bridge.ts`: the detector and its redaction mirror
 * refusing at different sizes is the drift this file exists to prevent. That
 * equality is no longer only asserted in prose —
 * `credential-scan-size-gate.test.ts` (HMA-23.AC7) pins the two constants
 * equal, so moving one without the other fails a test instead of a comment.
 */
export const MAX_REDACTION_INPUT_BYTES = 1_048_576;

/**
 * What the redactor substitutes for content it could not inspect.
 *
 * It is a marker rather than the original text because the refusal has to fail
 * CLOSED. This function is the last thing between a live secret and a report, so
 * content too large to read is content that must not be passed through — an
 * oversized input is exactly the shape an attacker would choose if returning the
 * input unredacted were the escape hatch. It is not `''` because a silent
 * disappearance reads downstream as "there was nothing here".
 */
export const REDACTION_WITHHELD = '[WITHHELD: content exceeds the redaction size limit and was not inspected]';

/**
 * Shape-anchored redaction that also reports WHICH shapes it resolved from the
 * value. `shapes` is sorted and deduped.
 *
 * `shapes` is empty when nothing shape-anchored matched — and also when the
 * content was refused unread for size, where `text` is `REDACTION_WITHHELD`.
 * Those two are distinguishable by the text, and neither may be reported as a
 * shape that was resolved: this function only names shapes it actually saw.
 *
 * This is the only function that can answer C9 honestly, because it is the only
 * point at which the matched rule — and therefore the shape id — is still in
 * hand.
 */
export function redactCredentialShapesReporting(content: string): {
  text: string;
  shapes: ShapeId[];
} {
  // The size gate, in front of the whole table — see `MAX_REDACTION_INPUT_BYTES`.
  if (Buffer.byteLength(content, 'utf-8') > MAX_REDACTION_INPUT_BYTES) {
    return { text: REDACTION_WITHHELD, shapes: [] };
  }

  let text = content;
  const shapes = new Set<ShapeId>();

  for (const rule of CREDENTIAL_REDACTION_RULES) {
    // `pattern` carries /g, so `replace` is a full scan; testing separately
    // would advance `lastIndex` on a shared literal. Compare instead.
    const before = text;
    text = text.replace(rule.pattern, rule.replacement);
    if (text !== before) shapes.add(rule.id);
  }

  return { text, shapes: [...shapes].sort() };
}

/**
 * Strip ALL credential-like content before sending to NanoMind.
 * This goes beyond the input sanitizer (which strips meta-instructions).
 * This strips actual secrets so NanoMind never sees real credentials.
 *
 * Even if the daemon is compromised, it cannot exfiltrate credentials
 * because it never received them.
 *
 * Redacts only values that carry a recognizable CREDENTIAL SHAPE — a vendor
 * prefix, a key block, a connection string. Every rule is anchored to a shape,
 * so it cannot destroy ordinary prose.
 *
 * Shared by both boundaries below so the shape list cannot drift between them.
 * A shape the compiler's detectors can report MUST appear here; see
 * `pinned-credential-shapes.test.ts`, which iterates BOTH detector lists.
 */
export function redactCredentialShapes(content: string): string {
  return redactCredentialShapesReporting(content).text;
}


/**
 * Daemon boundary. Shapes, plus an aggressive name-gated rule that redacts ANY
 * sufficiently long quoted value assigned to a password/secret/token/key
 * identifier, whether or not it looks like a credential.
 *
 * The over-breadth is deliberate HERE and only here: the output is an advisory
 * prompt, so a false positive costs a mangled token while a false negative
 * hands NanoMind a live secret.
 */
export function redactSecretsForNanoMind(content: string): string {
  return redactCredentialShapes(content).replace(
    /(?:password|secret|token|key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    (match) => `${match.split(/[=:]/)[0]}=[REDACTED]`,
  );
}

/**
 * Report boundary — for text that is rendered back to the USER (findings,
 * fix text, declared purpose).
 *
 * Same shapes, but the name-gated rule only fires on a value that could
 * plausibly BE a secret: no whitespace. That single condition is what
 * separates the two boundaries.
 *
 * Applying the daemon rule here was a measured regression. `key = "example
 * fixture value for tests only"` became `key=[REDACTED]`, destroying the
 * words `isTestOrDocContext` reads and flipping a scan from 98/exit-0 to
 * 69/exit-1; `token: "finance reporting analytics pipeline summaries"`
 * collapsed the word count `checkScopeMismatch` gates on from 6 to 1 and
 * silently dropped AST-SCOPE-001 — a check whose stated job is catching
 * capabilities hidden behind a benign-sounding purpose. Redacting prose the
 * user wrote is not a free trade here: it changes what the scanner reports.
 *
 * A real secret has no spaces, so the whitespace test keeps `password =
 * "hunter2xyz"` redacted while leaving prose intact.
 */
export function redactSecretsForReport(content: string): string {
  return redactSecretsForReportReporting(content).text;
}

/**
 * The report boundary, reporting which shapes it resolved FROM THE VALUE.
 *
 * The name-gated rule below contributes NO shape ids, and that is C9 stated as
 * code rather than as a convention: it fires on an IDENTIFIER
 * (`password`/`secret`/`token`/`key`) without ever inspecting what the value
 * is, so it cannot know which shape it removed — it cannot even know it removed
 * a credential. A finding redacted only by this rule is honestly
 * `redactionStatus: 'applied'` with `redactedShapes: []`.
 */
export function redactSecretsForReportReporting(content: string): {
  text: string;
  shapes: ShapeId[];
} {
  const shapePass = redactCredentialShapesReporting(content);
  const text = shapePass.text.replace(
    /(?:password|secret|token|key)\s*[=:]\s*['"]([^'"\s]{8,})['"]/gi,
    (match) => `${match.split(/[=:]/)[0]}=[REDACTED]`,
  );
  return { text, shapes: shapePass.shapes };
}

// ============================================================================
// Rule 6: AST Integrity Verification
// ============================================================================

/**
 * Verify AST hasn't been tampered with before any analyzer consumes it.
 * Every analyzer MUST call this before processing.
 */
export function assertASTIntegrity(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
): void {
  if (!ast.signature) {
    throw new SecurityError('AST has no signature. Refusing to process unsigned AST.');
  }
  if (!ast.contentHash) {
    throw new SecurityError('AST has no content hash. Refusing to process.');
  }
  if (!verifier(ast)) {
    throw new SecurityError(
      'AST signature verification FAILED. The AST may have been tampered with. ' +
      'This is a critical security event that should be investigated.'
    );
  }
}

export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

// ============================================================================
// Rule 7: Training Data Provenance
// ============================================================================

export interface TrainingDataProvenance {
  /** SHA-256 hash of the training sample */
  contentHash: string;
  /** Where this sample came from */
  source: 'registry_scan' | 'simulation' | 'attack_session' | 'hma_payload' | 'dvaa' | 'manual';
  /** Who/what labeled it */
  labeledBy: 'heuristic' | 'nanomind' | 'claude_review' | 'human';
  /** Confidence in the label */
  confidence: number;
  /** When it was created */
  createdAt: string;
  /** Has this been reviewed by Claude? */
  claudeReviewed: boolean;
  /** Signature of the provenance record */
  signature: string;
}

/**
 * Verify that a training sample has valid provenance.
 * Samples without provenance are rejected from training.
 */
export function verifyTrainingProvenance(provenance: TrainingDataProvenance): boolean {
  if (!provenance.contentHash) return false;
  if (!provenance.source) return false;
  if (!provenance.labeledBy) return false;
  if (provenance.confidence < 0 || provenance.confidence > 1) return false;

  // High-risk: samples from external sources must be Claude-reviewed
  if (provenance.source === 'registry_scan' && !provenance.claudeReviewed) {
    return false; // External data must be validated before training
  }

  return true;
}

// ============================================================================
// Audit Log
// ============================================================================

export interface NanoMindAuditEvent {
  timestamp: string;
  event: 'classification' | 'suppression_blocked' | 'ast_tamper_detected' | 'secret_redacted' | 'manipulation_detected' | 'consensus_override';
  details: string;
  artifactHash?: string;
  severity: 'info' | 'warning' | 'critical';
}

const auditLog: NanoMindAuditEvent[] = [];

/**
 * Log a NanoMind security event. These events are immutable and
 * should be forwarded to the transparency log.
 */
export function logSecurityEvent(event: Omit<NanoMindAuditEvent, 'timestamp'>): void {
  auditLog.push({
    ...event,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Get all audit events since a given timestamp.
 */
export function getAuditEvents(since?: string): NanoMindAuditEvent[] {
  if (!since) return [...auditLog];
  return auditLog.filter(e => e.timestamp >= since);
}
