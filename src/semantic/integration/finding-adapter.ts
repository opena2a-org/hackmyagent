/**
 * Finding Adapter
 *
 * Converts SemanticFinding (internal) → SecurityFinding (core scanner format).
 * This is the bridge between the semantic engine and the existing scanner.
 */

import type { SemanticFinding } from '../types';
import type { Evidence, Rationale, ConceptId } from '../../types/finding-evidence';
// Leaf module: pure text helpers, no node builtins, no scanner imports. The
// engine's zero-runtime-dependency property is about not reaching into the
// scanner or the filesystem, and this reaches neither.
import { resolveFindingLine } from '../../types/finding-location';

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
 *
 * `rawContent` (#368) is the analyzed file's own bytes, when the caller has
 * them. A semantic finding whose analyzer recorded no line used to arrive at
 * the renderer unlocatable — no `<file>:<N>`, no `Verify:` — and
 * `resolveFindingLine` recovers one from the finding's verbatim trigger
 * instead. It returns undefined rather than a default when nothing verbatim
 * can be found, which is the correct answer for the absence-shaped findings
 * (`SEM-PERM-002 Unrestricted Bash access`) that have no single trigger line.
 */
export function toSecurityFinding(
  finding: SemanticFinding,
  rawContent?: string,
): SecurityFinding {
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
    line: resolveFindingLine(
      { file: finding.file, line: finding.line, evidence: finding.evidence },
      rawContent,
    ),
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
 *
 * `readArtifact` is consulted only for a finding that has a file and no line,
 * so a scan pays for at most one read per unlocated finding. Callers without
 * the scanned tree in hand omit it and get the previous behaviour.
 */
export function toSecurityFindings(
  findings: SemanticFinding[],
  readArtifact?: (file: string) => string | undefined,
): SecurityFinding[] {
  return findings.map(f => {
    const needsLine = f.line === undefined && !!f.file;
    return toSecurityFinding(
      f,
      needsLine && readArtifact ? readArtifact(f.file) : undefined,
    );
  });
}
