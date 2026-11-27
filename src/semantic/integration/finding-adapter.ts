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
 * PRE-EMIT finding shape duplicated here so the semantic engine keeps zero
 * runtime dependencies (the import below is type-only and erased at compile).
 *
 * This interface mirrors `SecurityFindingDraft`, NOT the full
 * `SecurityFinding` — deliberately. This adapter's outputs are drafts: they
 * have not crossed the redaction boundary yet (they are emitted downstream at
 * the scanner's route points), so they must NOT carry `redactionStatus` /
 * `redactedShapes` — a detector is not in a position to know them. The
 * compile-time assertion after the interface makes drift a build error in
 * both directions the old "keep in sync" comment could not enforce: a field
 * added here that the canonical draft lacks, or a type that widens past it.
 * The exported NAME stays `SecurityFinding` because it is public on the `.`
 * and `./semantic` subpaths and renaming a published type is a breaking
 * change (ruled 2026-08-21).
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

// Drift assertions against the canonical draft (type-only import — erased at
// compile, so the zero-runtime-dependency property of this module holds).
// (1) Every key here must exist on `SecurityFindingDraft`, so a field the
// canonical type drops (or never had) is a build error here, not a silently
// stripped field at conversion. (2) A value of this shape must be assignable
// to the canonical draft, so a type widened past the canonical one fails.
// The canonical draft may grow fields this mirror lacks — that is additive
// and safe; the hazard this pins is the mirror inventing or widening.
import type { SecurityFindingDraft as _CanonicalDraft } from '../../hardening/security-check';
type _AdapterKeysExistOnDraft =
  Exclude<keyof SecurityFinding, keyof _CanonicalDraft> extends never ? true : never;
const _adapterKeysExistOnDraft: _AdapterKeysExistOnDraft = true;
void _adapterKeysExistOnDraft;
const _adapterAssignableToDraft = (f: SecurityFinding): _CanonicalDraft => f;
void _adapterAssignableToDraft;

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
 * WHICH DETECTORS REACH THAT RECOVERY. `SEM-PERM-002` and `SEM-PERM-003`
 * (`structural/permission-model.ts`, #496) do: they read the parsed settings,
 * so they quote the allow entries they matched as evidence with no line, and
 * the line is found here in the file's own bytes. `SEM-CRED-001`
 * (`structural/credential-context.ts`) and the bounded `SEM-INST-001`
 * (`structural/instruction.ts`, #734) also set `evidence`, but always with a
 * valid `line` AND `evidence.lines[0].n`, so `resolveFindingLine` returns at
 * step 1 without consulting `rawContent`. The other semantic findings that
 * LACK a line — `SEM-MCP-005/006` (cross-server and whole-file), the other
 * `SEM-MCP-*` checks when their search of the raw text finds no line (#644),
 * `SEM-INST-003/004`, `SEM-PERM-001`, `SEM-CRED-004` — set no `evidence`, so
 * there is no verbatim trigger to locate and the result is undefined whatever
 * the caller passes.
 *
 * The reader both `hardening/scanner.ts` call sites hand down is pinned by
 * `__tests__/hardening/semantic-line-recovery-real-scan.test.ts`, which runs a
 * real scan and fails when either call site drops it.
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
