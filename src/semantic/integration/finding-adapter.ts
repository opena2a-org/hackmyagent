/**
 * Finding Adapter
 *
 * Converts SemanticFinding (internal) → SecurityFinding (core scanner format).
 * This is the bridge between the semantic engine and the existing scanner.
 */

import type { SemanticFinding } from '../types';
import type { Evidence, Rationale, ConceptId } from '../../types/finding-evidence';

/**
 * SecurityFinding shape duplicated here to avoid a circular dependency —
 * the semantic engine has zero runtime dependencies.
 *
 * Keep this interface in sync with the canonical `SecurityFinding` in
 * `src/hardening/security-check.ts`. Drift here causes silently-stripped
 * fields when SemanticFinding → SecurityFinding conversion happens.
 */
export interface SecurityFinding {
  checkId: string;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  passed: boolean;
  message: string;
  fixable: boolean;
  fixed?: boolean;
  file?: string;
  line?: number;
  fix?: string;
  guidance?: string;
  attackClass?: string;
  evidence?: Evidence;
  rationale?: Rationale;
  concept?: ConceptId;
}

const CATEGORY_LABELS: Record<string, string> = {
  credential: 'Credential Protection',
  'mcp-config': 'MCP Configuration',
  instruction: 'Agent Instructions',
  permission: 'Permission Model',
};

/**
 * Convert a SemanticFinding to a SecurityFinding for the core scanner.
 */
export function toSecurityFinding(finding: SemanticFinding): SecurityFinding {
  return {
    checkId: finding.id,
    name: finding.title,
    description: finding.description,
    category: CATEGORY_LABELS[finding.category] || finding.category,
    severity: finding.severity === 'info' ? 'low' : finding.severity,
    passed: false,
    message: finding.rationale,
    fixable: finding.autoFixable,
    file: finding.file,
    line: finding.line,
    fix: finding.recommendation,
    guidance: finding.rationale,
    attackClass: finding.attackClass,
    evidence: finding.evidence,
    rationale: { plainEnglish: finding.rationale },
    concept: finding.concept,
  };
}

/**
 * Convert an array of SemanticFindings to SecurityFindings.
 */
export function toSecurityFindings(
  findings: SemanticFinding[]
): SecurityFinding[] {
  return findings.map(toSecurityFinding);
}
