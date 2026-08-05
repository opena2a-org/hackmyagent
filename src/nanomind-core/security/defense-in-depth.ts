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
 * Strip ALL credential-like content before sending to NanoMind.
 * This goes beyond the input sanitizer (which strips meta-instructions).
 * This strips actual secrets so NanoMind never sees real credentials.
 *
 * Even if the daemon is compromised, it cannot exfiltrate credentials
 * because it never received them.
 */
/**
 * Redact only values that carry a recognizable CREDENTIAL SHAPE — a vendor
 * prefix, a key block, a connection string. Every rule here is anchored to a
 * shape, so it cannot destroy ordinary prose.
 *
 * Shared by both boundaries below so the shape list cannot drift between them.
 * A shape the compiler's detectors can report MUST appear here; see
 * `pinned-credential-shapes.test.ts`, which iterates BOTH detector lists.
 */
export function redactCredentialShapes(content: string): string {
  let redacted = content;

  // API keys.
  //
  // The invariant is COVERAGE, not equality: this list must redact every shape
  // `CANONICAL_CREDENTIAL_PATTERNS` in the semantic compiler can DETECT, and it
  // may redact more. A shape detected but not redacted is the worst of both —
  // the scanner proves the secret is real, then forwards it to the daemon —
  // whereas redacting something that was not a credential costs only a mangled
  // token in an advisory prompt. `pinned-credential-shapes.test.ts` asserts
  // that direction. (`glpat-` is deliberately here and NOT in the detector.)
  //
  // These rules are deliberately NOT left-anchored, unlike the detector's.
  // Anchoring is an FP control, and the two sides want opposite defaults: a
  // false positive here is a mangled token, a false negative is a leaked
  // secret. Anchoring also broke adjacent tokens — `ghp_<36>ghp_<36>` redacted
  // the first and left the second verbatim, because the replacement consumed
  // the boundary the next match needed.
  //
  // Order matters here in a way it does not in the detector: `sk-proj-` and
  // `sk-ant-api` must be replaced BEFORE the generic `sk-` rule, or a project
  // key would be reported under the legacy label. The legacy rule's
  // alphanumeric-only class already excludes both, and the ordering makes that
  // independent of the class staying that way.
  redacted = redacted.replace(/sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_ANTHROPIC_KEY]');
  redacted = redacted.replace(/sk-proj-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_OPENAI_KEY]');
  redacted = redacted.replace(/sk-[a-zA-Z0-9]{48,}/g, '[REDACTED_OPENAI_KEY]');
  redacted = redacted.replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]');
  redacted = redacted.replace(/ghp_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/gho_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/ghs_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/ghu_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/github_pat_[a-zA-Z0-9_]{60,}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/glpat-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_GITLAB_TOKEN]');
  redacted = redacted.replace(/hf_[a-zA-Z0-9]{34,}/g, '[REDACTED_HUGGINGFACE_TOKEN]');
  redacted = redacted.replace(/npm_[a-zA-Z0-9]{36}/g, '[REDACTED_NPM_TOKEN]');
  redacted = redacted.replace(/sk_live_[0-9a-zA-Z]{24,}/g, '[REDACTED_STRIPE_KEY]');
  redacted = redacted.replace(/sk_test_[0-9a-zA-Z]{24,}/g, '[REDACTED_STRIPE_KEY]');
  redacted = redacted.replace(/SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, '[REDACTED_SENDGRID_KEY]');
  redacted = redacted.replace(/AIza[0-9A-Za-z_-]{35}/g, '[REDACTED_GOOGLE_KEY]');
  redacted = redacted.replace(/xox[baprs]-[a-zA-Z0-9-]{10,}/g, '[REDACTED_SLACK_TOKEN]');

  // AWS secret access key. The compiler's SECOND detector list
  // (`NAME_GATED_CREDENTIAL_PATTERNS`) reports this shape, so the coverage
  // invariant requires it here — its absence left a detected 40-character
  // secret rendering 33 characters into text, JSON, HTML and SARIF.
  //
  // The name anchor below MIRRORS the detector's anchor deliberately, and the
  // first attempt at this rule shows why that is not optional: it matched only
  // a literal `aws_secret_access_key`, while the detector also fires on
  // `secretAccessKey`, `awsSecretKey` and `secret_access_key`. All three were
  // detected and left verbatim, leaking the FULL 40 characters whenever the
  // value was unquoted — a narrower redactor than detector is the same drift
  // this rule exists to close, just one level down.
  //
  // The value class is intentionally WIDER than the detector's (`=` padding,
  // `{40,}` rather than exactly 40): over-redaction here costs a mangled
  // token, under-redaction leaks a live secret. Quotes stay optional because
  // the detector makes them optional; the generic name-gated rule below
  // requires quotes and therefore cannot cover the bare form.
  redacted = redacted.replace(
    /((?:aws.{0,16}?(?:secret|private).{0,16}?key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*["']?)([A-Za-z0-9/+=]{40,})/gi,
    '$1[REDACTED_AWS_SECRET]',
  );

  // Private key blocks. The header alone is enough: the detector fires on
  // `-----BEGIN … KEY-----` without requiring the closing marker, and a
  // truncated or single-line block would otherwise stay verbatim.
  redacted = redacted.replace(/-----BEGIN [A-Z ]+ KEY-----[\s\S]*?-----END [A-Z ]+ KEY-----/g, '[REDACTED_PRIVATE_KEY]');

  // Connection strings
  redacted = redacted.replace(/(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, '[REDACTED_CONNECTION_STRING]');

  return redacted;
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
  return redactCredentialShapes(content).replace(
    /(?:password|secret|token|key)\s*[=:]\s*['"]([^'"\s]{8,})['"]/gi,
    (match) => `${match.split(/[=:]/)[0]}=[REDACTED]`,
  );
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
