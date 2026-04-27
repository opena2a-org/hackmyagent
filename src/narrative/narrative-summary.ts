/**
 * NanoMind v3 1-paragraph summary generator — gated by input-classifier
 * v3.1, with a graceful-degrade path baked in.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4.1, §10)
 *
 * Per project memory `project_nanomind_v05_intelreport_task_mismatch.md`,
 * v0.5.0 fails JSON-schema validation on clean-scan inputs and
 * hallucinates attack classes for non-attack tasks. v3 has the same
 * task-scope problem ([CDS-024]). Until a NanoMind release ships that
 * targets the comprehension task properly, this module returns empty
 * strings on every code path. The renderer treats `''` as
 * "Comprehension data not yet available" and renders graceful-degrade.
 *
 * The interface is the v1 stub. When NanoMind v3 lands a comprehension
 * model, swap the implementation of `generateSummary` /
 * `generateBehaviorDescription` / `generateMisuseNarrative` with a real
 * call. The caller contract is intentionally narrow:
 *
 *   - Synchronous-friendly Promise<string> shape.
 *   - Never throws. Errors swallow into `''`.
 *   - Caller-controlled timeout via the per-call `timeoutMs` option.
 */
import type { SecurityAST } from "../nanomind-core/types.js";

/** Allowed artifact types per input-classifier v3.1. */
const ALLOWED_ARTIFACT_TYPES = new Set(["skill", "mcp_config"]);

/**
 * Result triple — mirrors the three NanoMind-sourced fields in
 * `PackageNarrative`.
 */
export interface NarrativeSummaryResult {
  /** PackageNarrative.summary — 2-4 sentence overview. */
  summary: string;
  /** SkillNarrative.behaviorDescription — 1-2 sentence behavior synopsis. */
  behaviorDescription: string;
  /** SkillNarrative.misuseNarrative — 2-4 sentence misuse explanation. */
  misuseNarrative: string;
  /**
   * True when NanoMind successfully produced text. False when the
   * gate refused, the model timed out, or generation errored. Callers
   * surface this in debug logs but do not treat it as user-visible.
   */
  generated: boolean;
}

export interface NarrativeSummaryOptions {
  /** Per-call timeout (defaults to 8s). */
  timeoutMs?: number;
  /** Whether to log model-call telemetry to stderr in --verbose mode. */
  verbose?: boolean;
}

/**
 * Input-classifier v3.1 gate. Returns true when the artifact is a
 * valid input for NanoMind v3 comprehension generation. Currently
 * narrows to `skill` and `mcp_config` artifact types — the only two
 * the v1 brief surfaces in the rich-context view.
 */
export function isAcceptedByInputClassifier(ast: SecurityAST): boolean {
  return ALLOWED_ARTIFACT_TYPES.has(ast.artifactType);
}

/**
 * Generate the three NanoMind-sourced narrative strings. Always
 * resolves; never rejects. v1 stub returns `''` for all three.
 *
 * Flow when wired up to a real NanoMind v3:
 *   1. Gate via `isAcceptedByInputClassifier`. Reject → return empty.
 *   2. Call into the local NanoMind daemon (or remote inference) with
 *      a comprehension prompt + the sanitized AST as context.
 *   3. Validate output: each string ≥ 1 sentence, ≤ 4096 chars,
 *      no model-of-the-week hallucination markers.
 *   4. On any failure (schema, timeout, daemon down, OOD output)
 *      → return empty strings + generated=false.
 */
export async function generateNarrativeSummary(
  ast: SecurityAST,
  _options: NarrativeSummaryOptions = {},
): Promise<NarrativeSummaryResult> {
  if (!isAcceptedByInputClassifier(ast)) {
    return emptyResult();
  }
  // v1 stub: NanoMind v3 comprehension is not wired up. Real
  // implementation lives in a follow-up branch keyed on the new
  // model release per [CHIEF-CDS] approval.
  return emptyResult();
}

/**
 * Empty result helper used by both the gate-rejected and stub paths
 * so the caller doesn't branch on "did the gate accept."
 */
export function emptyResult(): NarrativeSummaryResult {
  return {
    summary: "",
    behaviorDescription: "",
    misuseNarrative: "",
    generated: false,
  };
}
