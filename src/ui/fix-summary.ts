/**
 * The sentence that opens the fix report.
 *
 * "Fixed N issues" used to count every ATTEMPT, so a run whose only fix was
 * PROVEN not to have landed still opened in green with "Fixed 1 issue:". The
 * rule that replaced it: lead with what was confirmed, and a run with nothing
 * confirmed does not get to claim a repair.
 *
 * #285 — that rule lived as a nested ternary inside a `console.log` inside a
 * Commander action handler, so nothing could execute it. `cli.ts` builds its
 * program at import time, which is why its behaviours were only ever asserted
 * by grepping the source. Same "testable as a function" move #350 made for the
 * telemetry success policy and #285 made for the MCP tool payloads.
 *
 * The colour lives with the caller. This returns the tone so the sentence can
 * be asserted without ANSI, and so the tone/colour pairing is itself a fact a
 * test can pin rather than a coincidence of two ternaries agreeing.
 */

/** Which claim the run has earned. */
export type FixSummaryTone =
  /** Every attempted fix is either verified or was never checked. */
  | 'confirmed'
  /** Fixes were attempted and NONE was confirmed. */
  | 'none-confirmed'
  /** Some confirmed, some not. */
  | 'partial';

export interface FixSummary {
  tone: FixSummaryTone;
  /** The line, without colour codes. Always ends in ':' — the fix list follows. */
  text: string;
}

/**
 * `attempted` is the number of findings carrying a fix attempt; `verified` and
 * `unverified` are how the verification pass ruled on them. They do not have to
 * sum to `attempted`: a fix the pass never examined is neither.
 */
export function fixSummaryLine(
  attempted: number,
  verified: number,
  unverified: number,
): FixSummary {
  if (unverified === 0) {
    const suffix = verified > 0 ? ` (${verified} verified)` : '';
    return {
      tone: 'confirmed',
      text: `Fixed ${attempted} issue${attempted === 1 ? '' : 's'}${suffix}:`,
    };
  }

  const plural = attempted === 1 ? '' : 'es';
  if (verified === 0) {
    return {
      tone: 'none-confirmed',
      text: `Attempted ${attempted} fix${plural}, none confirmed:`,
    };
  }

  return {
    tone: 'partial',
    text: `Attempted ${attempted} fix${plural} — ${verified} verified, ${unverified} not confirmed:`,
  };
}
