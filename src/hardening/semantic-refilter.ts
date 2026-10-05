/**
 * The CLI's re-filter after the semantic (NanoMind) merge, shared by `secure`
 * and `check`'s local directory arm. Lives outside `cli.ts` so the ledger
 * contract it depends on can be tested in-process (#427).
 */

import type { HardeningScanner } from './scanner';
import type { ScanResult, SecurityFindingDraft } from './security-check';
import { summarizeSuppressed } from '../ui/verdict-band';

/**
 * Re-apply the scope and suppression filters after the semantic merge, and
 * record what they narrowed. Runs on `secure` and on `check`'s local
 * directory arm (#740), which runs the same scan through the same hook.
 *
 * #499 — re-filter from `result.allFindings`, NOT from
 * `nmResult.mergedFindings`. The semantic pass runs inside the scan and
 * therefore BEFORE `SCAN-UNREAD-001` is generated, so `mergedFindings` is the
 * merge of the static set as it stood at that moment and carries no
 * unread-input findings. Re-deriving the whole report from it would delete
 * them, taking #438's per-path disclosure with them and leaving exit 2 with
 * nothing named — the precise failure the scanner's own comment at the
 * generation site warns against. `allFindings` is the merged set with those
 * findings pushed on top.
 *
 * #427 — this pass drops findings AFTER `scan()` returned, but it needs no
 * entry of its own in `coverage.suppressedFailures`. The ledger is built inside
 * the scan from the post-merge array (the semantic pass runs in the ledger's
 * window, #499), and `isReportableFinding` is the same predicate the scanner's
 * own filter applies. So a finding the merge reintroduces and this pass drops
 * was already recorded. Moving the semantic pass back out of the scan, or
 * letting this predicate drift from the scanner's, reopens the gap;
 * `__tests__/hardening/semantic-refilter-ledger.test.ts` holds both.
 */
export async function refilterAfterSemanticMerge(
  scanner: HardeningScanner,
  result: ScanResult,
  targetDir: string,
): Promise<void> {
  const postMerge = result.allFindings || result.findings || [];
  const refiltered = await scanner.reapplyIgnoreFilters(postMerge, targetDir, result.projectType || 'library');
  // #450 — the semantic layer produces findings the scan pass never saw,
  // so this call can narrow scope where `scanInner` did not. Take the
  // wider of the two records rather than the later one, or a narrowing
  // disclosed by the static pass disappears from the report the moment the
  // semantic pass runs.
  if (scanner.lastOutOfScope.length > (result.outOfScope?.length ?? 0)) {
    result.outOfScope = scanner.lastOutOfScope;
  }
  // REPLACED, not merged. `nmResult.mergedFindings` is rebuilt from
  // `allFindings`, which still holds every finding `scanInner` suppressed,
  // so this pass re-derives the whole suppression set from the post-merge
  // array. Accumulating instead counted each suppressed finding twice and
  // printed `CONFIG-004 (critical x2)` for a single occurrence.
  result.suppressed = scanner.lastSuppressed.length > 0 ? scanner.lastSuppressed : undefined;
  // The disclosure's `matched` counts are recounted by the same call
  // over the same post-merge array as the two Row records above, so the
  // Σ-matched cross-check holds on what `--json` finally carries.
  // Presence rule unchanged: `lastHmaIgnore` is undefined exactly when
  // the target has no `.hmaignore`.
  result.hmaignore = scanner.lastHmaIgnore;
  if (result.allFindings) {
    // No cast. `reapplyIgnoreFilters` is generic over the finding type and
    // only marks and filters, so `refiltered` is still branded and assigns
    // directly. A cast here would have compiled just as quietly while
    // laundering the boundary guarantee at the one point downstream of it
    // that rebuilds both channels.
    result.allFindings = refiltered;
  }
  if (result.findings) {
    // Re-apply the same gates as the original filter:
    // 1. Failed OR fixed  2. Has file path  3. Applies to project type
    //
    // The `f.fixed` half is not optional. This filter claimed to mirror
    // the scanner's, but the scanner keeps fixed findings
    // (`if (!f.fixed && f.passed) return false`) while this dropped
    // every one of them. That silently deleted any finding a check
    // reported as `passed: <check>Fixed` — including one the
    // verification pass had just proved did NOT land — before
    // `countsAgainstScore` ran a few lines below, so the score was
    // recomputed from a list the unverified fix had been removed from.
    const projectType = result.projectType || 'library';
    result.findings = refiltered.filter((f) =>
      scanner.isReportableFinding(f, projectType)
    );
  }
}

type SuppressionRows = NonNullable<ScanResult['suppressed']>;

/**
 * Fold two suppression records into one, per (checkId, channel), in the order
 * `summarizeSuppressed` sorts. Expanded and re-summarised rather than
 * concatenated, so a check recorded by both passes is one row with the summed
 * count and the worst row stays first.
 */
function mergeSuppressionRows(...records: Array<SuppressionRows | undefined>): SuppressionRows {
  return summarizeSuppressed(
    records.flatMap((rows) =>
      (rows ?? []).flatMap((r) =>
        Array.from({ length: r.count }, () => ({
          checkId: r.checkId,
          name: r.name,
          category: r.category,
          severity: r.severity,
          suppressed: true,
          suppressedBy: r.suppressedBy,
          passed: false,
        })),
      ),
    ),
  );
}

/**
 * The re-filter for the report paths that run the semantic pass AFTER
 * `scan()` returned (`secure-openclaw`, `secure-nemoclaw`), which merge it
 * over `result.findings` rather than over `allFindings` (#460).
 *
 * `result.findings` no longer holds what the scan pass suppressed, so the
 * merged array this re-filters carries only findings that pass never saw.
 * The two records are therefore disjoint and ADDED: replacing the scan's
 * record with this call's, as `refilterAfterSemanticMerge` can because it
 * re-derives from the whole post-merge set, would drop every suppression the
 * scan pass made. The result carries both, so the caller can add the
 * suppressed penalties back at its risk level and exit code and name them,
 * as `secure` and `check` do. Returns the merged findings with every matched
 * one removed, the same removal the paths made before.
 */
export async function refilterAfterLateSemanticMerge<T extends SecurityFindingDraft>(
  scanner: HardeningScanner,
  result: ScanResult,
  mergedFindings: T[],
  targetDir: string,
): Promise<T[]> {
  const refiltered = await scanner.reapplyIgnoreFilters(mergedFindings, targetDir, result.projectType || 'library');
  const suppressed = mergeSuppressionRows(result.suppressed, scanner.lastSuppressed);
  const outOfScope = mergeSuppressionRows(result.outOfScope, scanner.lastOutOfScope);
  result.suppressed = suppressed.length > 0 ? suppressed : undefined;
  result.outOfScope = outOfScope.length > 0 ? outOfScope : undefined;
  return refiltered;
}
