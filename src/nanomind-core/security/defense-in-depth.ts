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
export function redactSecretsForNanoMind(content: string): string {
  let redacted = content;

  // API keys
  redacted = redacted.replace(/sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_ANTHROPIC_KEY]');
  redacted = redacted.replace(/sk-proj-[a-zA-Z0-9]{20,}/g, '[REDACTED_OPENAI_KEY]');
  redacted = redacted.replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]');
  redacted = redacted.replace(/ghp_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  redacted = redacted.replace(/glpat-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_GITLAB_TOKEN]');

  // Generic secret patterns
  redacted = redacted.replace(/-----BEGIN [A-Z ]+ KEY-----[\s\S]*?-----END [A-Z ]+ KEY-----/g, '[REDACTED_PRIVATE_KEY]');
  redacted = redacted.replace(/(?:password|secret|token|key)\s*[=:]\s*['"][^'"]{8,}['"]/gi, (match) => {
    const prefix = match.split(/[=:]/)[0];
    return `${prefix}=[REDACTED]`;
  });

  // Connection strings
  redacted = redacted.replace(/(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, '[REDACTED_CONNECTION_STRING]');

  return redacted;
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
