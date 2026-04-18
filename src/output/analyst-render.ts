/**
 * Pure helpers for rendering NanoMind generative findings in the check command.
 *
 * Kept separate from cli.ts so the transformations can be unit-tested without
 * spinning up the full check pipeline.
 */

export interface AnalystFindingLike {
  confidence: number;
  taskType: string;
  result: {
    threatLevel?: string;
    [key: string]: unknown;
  };
}

/**
 * A finding is renderable when it meets the confidence gate AND, for
 * threatAnalysis specifically, reports a severity above the noise floor.
 * Everything else falls through to the taskType-specific branches.
 */
export function isRenderableAnalystFinding(af: AnalystFindingLike): boolean {
  if (af.confidence < 0.50) return false;
  if (af.taskType === 'threatAnalysis') {
    const lvl = String(af.result.threatLevel ?? 'unknown').toUpperCase();
    if (lvl === 'LOW' || lvl === 'INFO' || lvl === 'NONE') return false;
  }
  return true;
}

/** Confidence threshold below which a CRITICAL claim is downgraded to HIGH. */
export const LOW_CONFIDENCE_CAP = 0.80;

/**
 * Cap CRITICAL severity to HIGH when confidence is below the calibration
 * threshold. The model emits CRITICAL on findings with hardcoded ~60%
 * confidence, which is not enough evidence to scream the loudest severity.
 */
export function capAnalystThreatLevel(
  rawLevel: string | undefined,
  confidence: number,
): { level: string; capped: boolean } {
  const upper = String(rawLevel ?? 'unknown').toUpperCase();
  if (confidence < LOW_CONFIDENCE_CAP && upper === 'CRITICAL') {
    return { level: 'HIGH', capped: true };
  }
  return { level: upper, capped: false };
}

/**
 * Render confidence as a number when it crosses the calibration threshold,
 * and as a qualitative label otherwise. Avoids displaying a hardcoded value
 * (e.g. exactly 60% on every finding) as if it were a real measurement.
 */
export function formatAnalystConfidence(
  confidence: number,
): { label: string; numeric: boolean } {
  if (confidence >= LOW_CONFIDENCE_CAP) {
    return { label: `${Math.round(confidence * 100)}%`, numeric: true };
  }
  return { label: 'low confidence', numeric: false };
}

export interface FormattedDescription {
  text: string;
  truncated: boolean;
}

/**
 * Normalize an LLM-generated markdown description for terminal output.
 *
 * LLMs often produce "## Analysis\n\nThis artifact is..." — rendering that
 * raw puts "Analysis" on its own orphan line and wastes vertical space. This:
 *   - drops entire header lines (not just the # chars)
 *   - drops bold markers
 *   - collapses blank lines to an em-dash separator
 *   - collapses single newlines to spaces
 *   - caps length for non-verbose callers
 */
export function formatAnalystDescription(
  raw: string,
  opts: { verbose: boolean; maxLen?: number } = { verbose: false }
): FormattedDescription {
  const maxLen = opts.maxLen ?? 240;
  const cleaned = String(raw)
    .replace(/^#{1,6}\s+[^\n]*\n+/gm, '')
    .replace(/\*\*/g, '')
    .replace(/\s*\n\s*\n\s*/g, ' — ')
    .replace(/\s*\n\s*/g, ' ')
    .trim();
  if (opts.verbose || cleaned.length <= maxLen) {
    return { text: cleaned, truncated: false };
  }
  return { text: cleaned.slice(0, maxLen - 3) + '...', truncated: true };
}
