/**
 * Where a finding is, derived — never invented.
 *
 * Two adapter boundaries convert a detector's own finding shape into the
 * `SecurityFinding` the renderer and `--json` consumers read:
 * `astFindingToSecurityFinding` (nanomind AST) and `toSecurityFinding`
 * (semantic engine). Both used to copy `line` straight through, so a detector
 * that never recorded a line produced a finding the reader cannot locate: no
 * `<file>:<N>` in the text report and no `Verify:` at all, because
 * `generateVerifyCommand` has no line to cite.
 *
 * `resolveFindingLine` is the one place that recovers a line at those
 * boundaries. It recovers, it does not guess:
 *
 *   1. an existing `line` is returned unchanged;
 *   2. a line the detector already cited in structured evidence is used;
 *   3. otherwise the finding's VERBATIM trigger is located in the raw artifact
 *      content, and its 1-based line returned — but ONLY when that trigger
 *      identifies exactly one place: long enough to be specific
 *      (`MIN_VERBATIM_TRIGGER_LENGTH`), not a bare word out of the risk-surface
 *      keyword vocabulary, and occurring exactly once in the content;
 *   4. otherwise `undefined`.
 *
 * Step 4 is the load-bearing one. Defaulting to `1` would satisfy every
 * "the finding has a line" assertion while pointing every Verify command at
 * the first line of the file — a citation that is confidently wrong is worse
 * than an absent one, which is the rule `generateVerifyCommand` was built on
 * in #141 and the rule this module keeps.
 *
 * Leaf module on purpose: no node builtins, no project imports beyond the
 * pure text helpers and the evidence types. The semantic engine documents
 * itself as having zero runtime dependencies and imports this from its
 * adapter.
 */

import type { Evidence } from './finding-evidence';
import { findLineFromString } from './text-position';

/**
 * Shortest trigger this module will accept as locatable.
 *
 * A trigger has to be specific enough that finding it somewhere in the file is
 * evidence that it is THE occurrence the detector meant. Three characters
 * ("key", "url") match hundreds of positions in an ordinary source file, so a
 * line derived from one is a coin flip dressed as a citation. Eight is the
 * point at which a substring of ordinary code stops being a coincidence; below
 * it, `resolveFindingLine` reports no line rather than a plausible one.
 */
export const MIN_VERBATIM_TRIGGER_LENGTH = 8;

/**
 * The keyword vocabulary `mapRiskSurfaces` (semantic-compiler.ts) emits as the
 * `evidence` of a CRED-HARVEST risk surface: `/password|credential|api[_-]?key|
 * secret|token/i.exec(content)?.[0]`. The evidence really is verbatim artifact
 * text, and it is still not a location.
 *
 * A DICTIONARY WORD IS A CATEGORY, NOT A PLACE. `credential` is 10 characters
 * and `password` is 8, so both clear the length floor above, and the first
 * occurrence of either is overwhelmingly a comment, an import, a type name or a
 * policy sentence rather than the flagged value. Measured: AST-CRED-001, a
 * CRITICAL that carries no line of its own, acquired one pointing at the first
 * occurrence of the WORD "password" in the file — a manufactured citation, and
 * the exact direction this module's docblock forbids. Pre-#368 that finding
 * rendered no line and no `Verify:`, which is the honest answer and the one
 * restored here.
 *
 * Matched WHOLE, case-insensitively: `credential` is rejected, and so is
 * `Credential`, while a longer trigger that merely CONTAINS the word
 * (`const credential = "sk-..."`) is a real excerpt and is kept.
 */
const GENERIC_TRIGGER_VOCABULARY = /^(?:password|credential|api[_-]?key|secret|token)$/i;

/**
 * True when `trigger` occurs exactly once in `content`.
 *
 * A TRIGGER EARNS A CITATION ONLY WHEN IT IDENTIFIES ONE PLACE. The search
 * below is a leftmost `indexOf`, so on a trigger that occurs three times it
 * returns the first — "a line where this text appears", which is not the same
 * claim as "the line the detector meant". With exactly one occurrence the two
 * cannot disagree; with more than one, there is no cheap tie-break that is
 * right, and the honest answer is no line.
 */
function occursExactlyOnce(content: string, trigger: string): boolean {
  const first = content.indexOf(trigger);
  if (first < 0) return false;
  return content.indexOf(trigger, first + 1) < 0;
}

/**
 * Extract the first cited line number from an Evidence record. Each evidence
 * shape exposes line numbers differently:
 *
 *   - positive : `lines[0].n`
 *   - absence  : `observed.lines[0].n`
 *   - mixed    : `positive.lines[0].n`
 *
 * Returns undefined when the evidence carries no line citations (e.g. an
 * absence finding whose observed-block is summary-only).
 */
export function firstLineFromEvidence(evidence: Evidence | undefined): number | undefined {
  if (!evidence) return undefined;
  if (evidence.kind === 'positive') {
    return evidence.lines[0]?.n;
  }
  if (evidence.kind === 'absence') {
    return evidence.observed.lines[0]?.n;
  }
  if (evidence.kind === 'mixed') {
    return evidence.positive.lines[0]?.n;
  }
  return undefined;
}

/** A finding as this module needs to see it — location data only. */
export interface LocatableFinding {
  file?: string;
  line?: number;
  /**
   * Structured evidence (semantic engine) or the AST analyzers' evidence
   * string, which is a verbatim substring of the artifact at most emit sites
   * and a dedupe rollup label (`[5 instances across: ...]`) at the rest. The
   * rollup is simply not found in the content, which is the correct answer for
   * it — a rolled-up finding has no single location.
   */
  evidence?: Evidence | string;
}

/** True for a usable 1-based line number. */
function isUsableLine(line: number | undefined): line is number {
  return line !== undefined && Number.isInteger(line) && line >= 1;
}

/**
 * The verbatim strings this finding claims to have seen in the artifact, most
 * specific first. Only strings the detector copied out of the artifact belong
 * here — never a rendered message, description or fix, none of which are
 * artifact text.
 */
export function verbatimTriggers(evidence: Evidence | string | undefined): string[] {
  if (evidence === undefined) return [];
  if (typeof evidence === 'string') return [evidence];
  if (evidence.kind === 'positive') return evidence.lines.map(l => l.content);
  if (evidence.kind === 'absence') return evidence.observed.lines.map(l => l.content);
  if (evidence.kind === 'mixed') {
    return [
      ...evidence.positive.lines.map(l => l.content),
      ...evidence.absence.observed.lines.map(l => l.content),
    ];
  }
  return [];
}

/**
 * The 1-based line for `finding`, or undefined when none can be derived from
 * data the detector actually produced.
 *
 * `rawContent` is the artifact's own bytes as read at the calling boundary.
 * Pass `undefined` when the boundary genuinely does not have them: the trigger
 * search is then skipped and the function falls through to `undefined` rather
 * than substituting a default.
 */
export function resolveFindingLine(
  finding: LocatableFinding,
  rawContent: string | undefined,
): number | undefined {
  if (isUsableLine(finding.line)) return finding.line;
  // A line with no file is not a citation — there is nothing to open.
  if (!finding.file) return undefined;

  const cited = typeof finding.evidence === 'string'
    ? undefined
    : firstLineFromEvidence(finding.evidence);
  if (isUsableLine(cited)) return cited;

  if (!rawContent) return undefined;

  for (const trigger of verbatimTriggers(finding.evidence)) {
    const trimmed = trigger.trim();
    if (trimmed.length < MIN_VERBATIM_TRIGGER_LENGTH) continue;
    // A word out of the risk-surface keyword vocabulary is a category, not a
    // place — and two of them clear the length floor. See the constant.
    if (GENERIC_TRIGGER_VOCABULARY.test(trimmed)) continue;
    // Ambiguous is the same as absent: see `occursExactlyOnce`.
    if (!occursExactlyOnce(rawContent, trimmed)) continue;
    const line = findLineFromString(rawContent, trimmed);
    if (isUsableLine(line)) return line;
  }

  return undefined;
}
