/**
 * Pure helpers for character-offset → line-number conversion.
 *
 * Detectors that match against a regex's `m.index` need a 1-based line
 * number to populate `SecurityFinding.line` so `generateVerifyCommand()`
 * can emit a real `sed -n 'Np' file` Verify (issue #141).
 */

/**
 * Convert a 0-based character offset within `content` to a 1-based line
 * number.
 *
 * - Empty content or non-positive offset → 1.
 * - Offset past the end → clamps to the line of the final character.
 * - Counts only `\n`; `\r` carriage returns within `\r\n` pairs are
 *   ignored, which matches how editors number lines.
 */
export function lineFromOffset(content: string, offset: number): number {
  if (!content || offset <= 0) return 1;
  const clamped = Math.min(offset, content.length);
  let line = 1;
  for (let i = 0; i < clamped; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * Locate `needle` inside `artifactContent` and return the 1-based line
 * number of its first occurrence. Returns undefined when either argument
 * is missing/empty or the needle isn't found.
 *
 * AST-level findings carry their evidence as a verbatim substring of the
 * artifact (Capability.evidence, Constraint.text, RiskSurface.evidence).
 * The AST itself is signed and doesn't carry line numbers, so analyzers
 * re-derive them at emit time from the unsigned source content the caller
 * passes in (issue #141, extended to prompt/scope/governance in #147).
 */
export function findLineFromString(
  artifactContent: string | undefined,
  needle: string | undefined,
): number | undefined {
  if (!artifactContent || !needle) return undefined;
  const trimmed = needle.trim();
  if (!trimmed) return undefined;
  const idx = artifactContent.indexOf(trimmed);
  if (idx < 0) return undefined;
  return lineFromOffset(artifactContent, idx);
}
