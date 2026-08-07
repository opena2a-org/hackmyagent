/**
 * The scope disclosure `check --json` was missing. Closes #388.
 *
 * `check <dir>` runs the NanoMind semantic artifact matrix and NOT the static
 * check suite. The text channel says so four separate ways on the same bytes —
 * the score line reads `Quick scan`, the Checks line reads
 * `N static not run (quick scan)`, the follow-up names `secure` and the
 * categories it adds, and a clean verdict says outright what was not
 * evaluated. The machine channel said none of it: a caller reading
 * `{"risk":"low"}` could not tell "ran the suite and found nothing" from "did
 * not run the suite".
 *
 * This is #400 one command over. #400 landed a measured `coverage` object on
 * `secure --json` one commit before `check`'s JSON was cut into a release and
 * never touched `check`, so a single build shipped one command that disclosed
 * its coverage and one that did not.
 *
 * The key is `coverage` and the entries are `CategoryCoverage`, the same name
 * and the same vocabulary `secure --json` already uses, so a consumer has one
 * shape to read rather than two. The values are not asserted: they come out of
 * `summarizeCoverage` with an EMPTY execution ledger, which is the literal
 * truth — no static check ran, so no static category can claim evidence — and
 * the semantic matrix earns `examined` only where it actually reported a
 * finding, by the ledger's own rule that a finding proves its category was
 * examined.
 */
import {
  summarizeCoverage,
  SEMANTIC_PREFIXES,
  type CategoryCoverage,
  type CoverageTruncation,
} from '../hardening/coverage-ledger';

export interface QuickScanCoverage {
  /** Discriminates this from `secure`'s full-suite coverage on the same key. */
  mode: 'quick-scan';
  /** Artifacts the semantic matrix compiled. */
  semanticArtifactsCompiled: number;
  /** Size of the static suite that did NOT run. */
  staticChecksNotRun: number;
  /**
   * Always empty here, and stated rather than omitted: an absent ledger and an
   * empty one are different claims, and this one is empty because no static
   * check executed.
   */
  executions: readonly never[];
  /** Caps that stopped a layer short of the whole tree. */
  truncations: CoverageTruncation[];
  /**
   * Exhaustive per-category rollup, and the only category vocabulary in this
   * payload.
   *
   * The text channel's scope sentence names a highest-consequence subset
   * (`QUICK_SCAN_UNEVALUATED_CATEGORIES`) in its own labels, and two of those
   * labels are not the ledger's: it says `MCP config` where the ledger says
   * `MCP`, and `file permissions` where `PERM` rolls up under `sandbox`.
   * Shipping that subset here would put a second vocabulary in the payload for
   * no information a consumer does not already get from this field, so it is
   * not shipped. The correspondence is held instead by
   * `__tests__/check/quick-scan-coverage.test.ts`, which fails if either side
   * is renamed — a mismatch becomes a red test rather than two spellings of
   * the same category reaching a caller.
   */
  categories: CategoryCoverage[];
  /** The command that does evaluate them, as the user would type it. */
  fullAuditCommand: string;
}

export function quickScanCoverage(input: {
  /** Files the semantic pass compiled. */
  compiledArtifacts: number;
  /** True when the semantic pass hit its file cap. */
  compileSetTruncated?: boolean;
  /** Check IDs of the findings this run actually reported. */
  observedCheckIds: readonly string[];
  /** `getCheckCounts().static` — the advertised suite this run skipped. */
  staticCheckCount: number;
  /** Target for the follow-up command, as the user typed it. */
  fullAuditTarget: string;
}): QuickScanCoverage {
  const truncations: CoverageTruncation[] = input.compileSetTruncated
    ? [{
        layer: 'semantic',
        cap: input.compiledArtifacts,
        prefixes: [...SEMANTIC_PREFIXES],
        reason:
          `semantic pass capped at ${input.compiledArtifacts} files — source beyond the cap was not compiled`,
      }]
    : [];

  return {
    mode: 'quick-scan',
    semanticArtifactsCompiled: input.compiledArtifacts,
    staticChecksNotRun: input.staticCheckCount,
    executions: [],
    truncations,
    categories: summarizeCoverage([], truncations, {
      observedCheckIds: input.observedCheckIds.filter(Boolean),
      filesReadByCategory: {},
    }),
    fullAuditCommand: `secure ${input.fullAuditTarget}`,
  };
}
