/**
 * Pure label/copy helpers for the `check skill:` / `check mcp:` /
 * `check <local-path>` quick-scan rendering path. Closes #136.
 *
 * These are split out so the label decisions are unit-testable without
 * spawning the CLI or capturing stdout. The integration test in
 * `__tests__/cli/check-skill-quick-scan-label.test.ts` exercises the
 * full rendering chain end-to-end (spawn-gated on corpus availability);
 * the unit tests in `__tests__/ui/quick-scan-labels.test.ts` gate the
 * label logic itself in every CI run.
 */

import { citationTarget } from './shell-quote';

export interface QuickScanContext {
  /** Target string emitted in the follow-up line — path or name as the user typed it. */
  fullAuditTarget: string;
}

/**
 * Categories the quick-scan matrix does not evaluate at all.
 *
 * `check <target>` runs only the NanoMind semantic artifact matrix; the
 * static rule suite never executes. These are the highest-consequence
 * categories that silence covers, ordered by consequence. `credentials`
 * leads because it is what made #200 dangerous rather than merely
 * imprecise: a `check`-only user with an un-ignored `.env` was told the
 * directory looked safe.
 */
export const QUICK_SCAN_UNEVALUATED_CATEGORIES = [
  'credentials',
  'git hygiene',
  'MCP config',
  'file permissions',
] as const;

/** Display values for the Observations block under a narrowed quick scan. */
export interface QuickScanScopeDisclosure {
  /** Replacement Checks line — must not imply the static suite ran. */
  checks: string;
  /** Replacement Categories line for when nothing in the narrow matrix fired. */
  categories: string;
  /** Scope note appended to the Categories line when findings DO exist. */
  categoriesSuffix: string;
  /** Replacement Verdict for a quick scan that found nothing. */
  cleanVerdict: string;
}

/**
 * Build the honest scope disclosure for a quick scan (closes #200).
 *
 * Pre-fix, a `check <localdir>` that found nothing rendered:
 *
 *   Checks      310 static · 1 semantic (NanoMind AST) · 0 skipped
 *   Categories  credentials, MCP, network, ... + 16 more  (all clear)
 *   Verdict     No security issues detected. This local project looks safe to use.
 *
 * All three lines were false. The static suite never ran, so it could not
 * have cleared 310 checks or 25 categories, and "safe to use" asserted a
 * verdict over evidence the analyzer never looked at — while `secure` on
 * the same bytes reported 1 CRITICAL + 2 HIGH.
 *
 * The score line is already labeled "Quick scan" and carries a follow-up
 * pointer (#136); this closes the remaining three surfaces so no line in
 * the block overstates coverage.
 */
export function quickScanScopeDisclosure(opts: {
  /** Advertised static suite size, from getCheckCounts().static. */
  staticCount: number;
  /** Artifacts the semantic matrix actually compiled. */
  semanticCount: number;
  /** Target string as the user typed it. */
  fullAuditTarget: string;
}): QuickScanScopeDisclosure {
  const { staticCount, semanticCount } = opts;
  const unevaluated = QUICK_SCAN_UNEVALUATED_CATEGORIES.join(', ');
  // #273 — `secure <target>` is a command to paste, and the target arrives as
  // the user typed it.
  const fullAuditTarget = citationTarget(opts.fullAuditTarget);

  return {
    // Lead with what ran, then state plainly what did not. The suite size
    // is still cited so the reader can size the gap.
    checks: `${semanticCount} semantic (NanoMind AST) · ${staticCount} static not run (quick scan)`,
    categories: `semantic artifact matrix only  (${staticCount} static checks not evaluated)`,
    categoriesSuffix: `  · ${staticCount} static checks not evaluated`,
    cleanVerdict:
      `No issues in the semantic artifact matrix. This did NOT evaluate ${unevaluated} — ` +
      `run \`secure ${fullAuditTarget}\` before trusting it.`,
  };
}

/**
 * Score-line label. "Quick scan" under the narrowed matrix
 * (NanoMind semantic only); "Security" otherwise (the full static-check
 * audit via `secure`, sized by getCheckCounts()).
 */
export function scoreLineLabel(quickScan?: QuickScanContext): "Security" | "Quick scan" {
  return quickScan ? "Quick scan" : "Security";
}

/**
 * Whether to render the "Path forward: N -> M by fixing X critical + Y high"
 * recovery-math line. Suppressed under quickScan because the narrowed matrix
 * cannot predict the post-fix score against the broader full-audit matrix —
 * showing "78 -> 100 by fixing 1 critical" implies the user can reach 100
 * by addressing only quick-scan findings, when `secure` will surface
 * additional supply-chain and hygiene findings the quick scan never ran.
 */
export function shouldRenderPathForward(opts: {
  quickScan?: QuickScanContext;
  critical: number;
  high: number;
}): boolean {
  if (opts.quickScan) return false;
  return opts.critical > 0 || opts.high > 0;
}

/**
 * Plain text of the follow-up line directing the user to `secure` for the
 * full audit. Returned without color codes so callers paint it in their own
 * palette (HMA / ai-trust use different palette objects).
 */
export function quickScanFollowupText(quickScan: QuickScanContext): string {
  // Names the categories `secure` actually adds. The prior copy said
  // "supply-chain + skill-hygiene", which understated the gap: the
  // categories that matter most here are credentials and git hygiene,
  // and omitting them is what let #200 read as a minor coverage note
  // rather than the reason not to trust the verdict.
  return (
    `Run \`secure ${citationTarget(quickScan.fullAuditTarget)}\` for the full audit ` +
    `(adds ${QUICK_SCAN_UNEVALUATED_CATEGORIES.join(', ')}).`
  );
}

/**
 * Left-hand labels the Observations block prints, and the column they sit in.
 *
 * A label of exactly `OBSERVATION_LABEL_WIDTH` leaves no separator after
 * `padEnd` and runs straight into its value — `Not examinedA2A, CVE, …`
 * shipped that way twice during one change. `observation-labels.test.ts`
 * holds every entry strictly under the width so a third spelling cannot.
 */
export const OBSERVATION_LABEL_WIDTH = 12;

export const OBSERVATION_LABELS = {
  unexamined: 'Unexamined',
  coverage: 'Coverage',
  // #421 — categories that ran a check which did not pass, where the result
  // was not shown because it carried no evidence to point at. Neither `clear`
  // nor a finding. Without a name for that third state, withdrawing the
  // `clear` claim would just leave an unexplained gap in the tally.
  unresolved: 'Unresolved',
} as const;
