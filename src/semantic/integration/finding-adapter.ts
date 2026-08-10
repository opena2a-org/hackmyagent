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
 * them, so `resolveFindingLine` can recover a line from a finding's verbatim
 * trigger. It returns undefined rather than a default when nothing verbatim
 * can be found, which is the correct answer for the absence-shaped findings
 * (`SEM-PERM-002 Unrestricted Bash access`) that have no single trigger line.
 *
 * NO DETECTOR IN `src/semantic/` REACHES THAT RECOVERY TODAY, and an earlier
 * revision of this docblock claimed it did. Enumerated: `SEM-CRED-001`
 * (`structural/credential-context.ts`) is the only site that sets `evidence`
 * at all, and it always sets a valid `line` AND `evidence.lines[0].n`, so
 * `resolveFindingLine` returns at step 1 without consulting `rawContent`.
 * Every semantic finding that LACKS a line — `SEM-MCP-001..008`,
 * `SEM-INST-003/004`, `SEM-PERM-001/002/003`, `SEM-CRED-004` — sets no
 * `evidence`, so there is no verbatim trigger to locate and the result is
 * undefined whatever the caller passes.
 *
 * So the parameter is wiring ahead of its producers, not a live recovery path:
 * dropping the reader argument at both `hardening/scanner.ts` call sites leaves
 * the whole suite green and `secure --json` byte-identical, which was measured.
 * It is kept because the fix for those detectors is to make them carry
 * evidence, and this is the boundary that will consume it — but until then
 * nothing here changes behaviour, and the docblock must not imply otherwise.
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
