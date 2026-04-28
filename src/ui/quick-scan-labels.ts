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

export interface QuickScanContext {
  /** Target string emitted in the follow-up line — path or name as the user typed it. */
  fullAuditTarget: string;
}

/**
 * Score-line label. "Quick scan" under the narrowed matrix
 * (NanoMind semantic only); "Security" otherwise (full 209-static-check
 * audit via `secure`).
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
  return `Run \`secure ${quickScan.fullAuditTarget}\` for the full audit (adds supply-chain + skill-hygiene checks).`;
}
