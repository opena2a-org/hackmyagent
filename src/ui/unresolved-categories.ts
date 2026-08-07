/**
 * #421 — which categories may NOT be reported `clear`, because a check in them
 * matched something in the target and its finding was dropped before it
 * reached the user.
 *
 * Split out of `cli.ts` so it is unit-testable without spawning a scan. The
 * scoping that makes a finding disappear (`findingAppliesTo` against the
 * detected project type) fires on 23 narrow-scoped checks that emit a file,
 * but reproducing one end-to-end needs a project that both trips such a check
 * AND is not detected as the type that check belongs to — the two conditions
 * pull against each other, and no natural fixture was found. A guard nobody can
 * distinguish from its absence is not a guard, so the logic lives here and is
 * exercised directly.
 */

import { buildCategorySummaries } from '@opena2a/cli-ui';

/**
 * The identity of a check whose failed finding the scanner silenced. Mirrors
 * `ScanResult['coverage']['suppressedFailures']` — no paths, no messages.
 */
export interface SuppressedFailureIdentity {
  checkId: string;
  name: string;
  category: string;
  severity: string;
}

/**
 * Category LABELS (the renderer's vocabulary, not the finding's `category`
 * field) that hold at least one silenced detection.
 *
 * Bucketed with `buildCategorySummaries`, the same function the real findings
 * go through, because the two vocabularies differ: `LOG-*` findings carry
 * `category: 'logging'` and render under the label `audit`, `SESSION-*` carry
 * `session-security` and render under `session`. Keying off the raw field
 * silently matches only the handful of names that coincide.
 */
export function suppressedCategoryLabels(
  suppressed: readonly SuppressedFailureIdentity[],
): Set<string> {
  if (suppressed.length === 0) return new Set();
  return new Set(
    buildCategorySummaries(
      suppressed.map(s => ({
        checkId: s.checkId,
        name: s.name,
        category: s.category,
        severity: s.severity as 'critical' | 'high' | 'medium' | 'low',
        passed: false,
      })),
    )
      .filter(c => !c.clear)
      .map(c => c.name),
  );
}

/** A category summary as the renderer models it. */
export interface CategoryClearState {
  name: string;
  clear: boolean;
}

/**
 * Names of the categories to take OUT of the clear bucket.
 *
 * A category qualifies only when all three hold: it currently reads `clear`
 * (a category already showing a finding needs no correction), the run actually
 * EXAMINED it (an unexamined category is already disclosed as such and must
 * not be double-reported), and it holds a silenced detection.
 *
 * `examined` is passed as a predicate rather than a map so the caller keeps
 * ownership of what "examined" means; when coverage is absent the caller
 * supplies a predicate that is always false, which yields an empty result —
 * withdrawing `clear` while the disclosure line cannot render would be the
 * silent omission this whole change exists to prevent.
 */
export function unresolvedCategoryNames(
  summaries: readonly CategoryClearState[],
  isExamined: (name: string) => boolean,
  suppressedLabels: ReadonlySet<string>,
): string[] {
  return summaries
    .filter(c => c.clear && suppressedLabels.has(c.name) && isExamined(c.name))
    .map(c => c.name);
}
