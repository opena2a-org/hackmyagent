/**
 * #393 — the Categories line accounts for every failing finding.
 *
 * The shared renderer (`@opena2a/cli-ui`) prints only the WORST severity of
 * each category, so a tree with a critical and a high in `credentials`
 * printed:
 *
 *   Categories  credentials (1 critical) · git hygiene (1 low) · 23 others clear
 *   ── Findings ──
 *   1 critical  1 high  1 low
 *
 * The high was counted in the bucket and then dropped by the formatter. The
 * line summed to 2 while Findings said 3, and a reader who fixed what
 * Categories listed had not fixed what Findings listed. Every non-zero
 * severity is now named, worst first, so the per-category counts sum to the
 * Findings summary.
 *
 * Split out of `cli.ts` so it is unit-testable without spawning a scan.
 */

import type { CategorySummary } from '@opena2a/cli-ui';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

/**
 * `2 critical, 1 high` — every severity with a non-zero count, worst first.
 * Joined with a comma, never with `·`: `·` separates categories on the line,
 * and readers (and tests) split on it to count them.
 */
export function formatCategoryCounts(counts: CategorySummary['counts']): string {
  return SEVERITY_ORDER
    .filter(sev => counts[sev] > 0)
    .map(sev => `${counts[sev]} ${sev}`)
    .join(', ');
}

/**
 * The Categories line value when at least one category holds a finding, or
 * `undefined` when none does — the zero-findings rendering (`… (all clear)`)
 * is the renderer's and is left alone.
 *
 * Same shape as the renderer's line: the categories with findings in input
 * order, then a `N others clear` tail for the clear buckets that remain.
 */
export function formatCategoriesLine(categories: readonly CategorySummary[]): string | undefined {
  const withFindings = categories.filter(c => !c.clear);
  if (withFindings.length === 0) return undefined;
  const clearCount = categories.length - withFindings.length;
  const named = withFindings.map(c => {
    const counts = formatCategoryCounts(c.counts);
    return counts ? `${c.name} (${counts})` : c.name;
  });
  const tail = clearCount > 0 ? ` · ${clearCount} others clear` : '';
  return `${named.join(' · ')}${tail}`;
}
