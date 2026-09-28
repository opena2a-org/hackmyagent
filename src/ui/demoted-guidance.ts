/**
 * Guidance for a finding whose severity was lowered after its guidance was
 * written (#287).
 *
 * The semantic layer writes a finding's guidance while the finding is still at
 * its detected severity, so a CRITICAL opens with "Critical in this context
 * because …" or "Critical because …". A package scan then lowers test-file and
 * build-file findings to LOW, and the card printed `LOW` directly above a
 * sentence calling the finding critical — the reader cannot tell which to
 * believe.
 *
 * The rewrite keeps the analyzer's reason and states both facts in order: why
 * it is LOW here, then what it would be in runtime code. Guidance with no
 * severity opener keeps its text and gains only the first sentence.
 */

export type DemotionReason = 'test' | 'build';

const CRITICAL_OPENER = /^Critical(?: in this context)? because /;

export function guidanceAfterDemotion(
  guidance: string | undefined,
  originalSeverity: string,
  reason: DemotionReason,
): string {
  const where = reason === 'test'
    ? 'it is in a test file'
    : 'it is in a build, CI or tooling file';
  const lead = `LOW here because ${where}, which is not a runtime attack surface (detected as ${originalSeverity.toUpperCase()}).`;
  const rest = (guidance ?? '').trim();
  if (!rest) return lead;
  return `${lead} ${rest.replace(CRITICAL_OPENER, 'In runtime code it would be critical because ')}`;
}
