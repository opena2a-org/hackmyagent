/**
 * Finding evidence schema (v2 spine).
 *
 * Standard: every finding emitted by HMA must carry structured evidence,
 * a plain-English rationale, and (when applicable) a concept tag for an
 * unfamiliar primitive the user is being asked to adopt. See
 * `~/.claude/instructions/cli-finding-ux-standard.md` for the contract.
 *
 * This module is the type-level spine. Population at emit sites and the
 * renderer behavior (per-scan dedupe, first-occurrence-expanded explainer)
 * land in #138 / #141 / #142.
 */

/** Positive evidence — "we saw X bad thing at line N." */
export interface PositiveEvidence {
  kind: 'positive';
  lines: Array<{
    /** 1-based line number in the artifact. */
    n: number;
    /** Verbatim line content as the detector saw it. */
    content: string;
    /** What makes this line dangerous in context. Finding-specific, not boilerplate. */
    why: string;
  }>;
}

/** Absence-of-defense evidence — "the artifact does Z but lacks Y." */
export interface AbsenceEvidence {
  kind: 'absence';
  observed: {
    lines: Array<{
      /** 1-based line number in the artifact. */
      n: number;
      /** Verbatim line content showing the high-risk capability. */
      content: string;
    }>;
    /** Plain-English summary of what the artifact does that requires constraint. */
    summary: string;
  };
  expected: Array<{
    /** Constraint name (e.g., "trust-hierarchy", "override-resistance"). */
    constraint: string;
    /** Why this constraint matters given the observed behavior. */
    rationale: string;
  }>;
}

/** Mixed — both positive evidence and absence-of-defense apply. */
export interface MixedEvidence {
  kind: 'mixed';
  positive: Omit<PositiveEvidence, 'kind'>;
  absence: Omit<AbsenceEvidence, 'kind'>;
}

/** Discriminated union — narrow on `kind`. */
export type Evidence = PositiveEvidence | AbsenceEvidence | MixedEvidence;

/**
 * Plain-English rationale grounded in the evidence.
 *
 * For deterministic detectors this is templated from the evidence.
 * For NanoMind behavioral findings this is generated and grounded in the
 * cited lines. Either way the value must be finding-specific — not
 * byte-identical across siblings in the same scan.
 */
export interface Rationale {
  plainEnglish: string;
}

/**
 * Concept identifier for an unfamiliar primitive a fix recommends.
 *
 * The renderer dedupes by concept per scan: first occurrence shows the
 * curated explainer (from `src/ui/concept-explainers.ts`), subsequent
 * occurrences collapse to a one-line back-reference.
 */
export type ConceptId =
  | 'soul-governance'
  | 'secretless-vault'
  | 'mcp-tool-isolation'
  | 'injection-resistance'
  | 'trust-hierarchy'
  | 'signing-and-pinning';

/** Type guard — narrow `Evidence` to `PositiveEvidence`. */
export function isPositiveEvidence(e: Evidence): e is PositiveEvidence {
  return e.kind === 'positive';
}

/** Type guard — narrow `Evidence` to `AbsenceEvidence`. */
export function isAbsenceEvidence(e: Evidence): e is AbsenceEvidence {
  return e.kind === 'absence';
}

/** Type guard — narrow `Evidence` to `MixedEvidence`. */
export function isMixedEvidence(e: Evidence): e is MixedEvidence {
  return e.kind === 'mixed';
}

/** Runtime validation — useful for JSON deserialization boundaries. */
export function isValidEvidence(value: unknown): value is Evidence {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as { kind?: unknown };
  return v.kind === 'positive' || v.kind === 'absence' || v.kind === 'mixed';
}

/** Runtime validation — useful for JSON deserialization boundaries. */
export function isConceptId(value: unknown): value is ConceptId {
  return (
    value === 'soul-governance' ||
    value === 'secretless-vault' ||
    value === 'mcp-tool-isolation' ||
    value === 'injection-resistance' ||
    value === 'trust-hierarchy' ||
    value === 'signing-and-pinning'
  );
}
