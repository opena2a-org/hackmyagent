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
