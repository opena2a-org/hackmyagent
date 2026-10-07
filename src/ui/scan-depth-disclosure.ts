/**
 * #507 — the score line's denominator at `--scan-depth quick`.
 *
 * A quick scan runs 6 of the orchestrated check groups and records the rest as
 * skipped. On a tree holding `src/util.js`, a `.gitignore` and a `package.json`
 * with no lock file it printed `Security ━━━━ 98/100`, the same line, at the
 * same width, as a standard scan that ran every group — and the standard scan
 * of that tree scored 93, because a group quick skipped found the missing lock
 * file. The Checks line further down did say `6 of 63 check groups ran`, but
 * the headline number stood alone above it.
 *
 * The exit code is not this module's business: a user passing
 * `--scan-depth quick` has consented to the reduced depth, and quick keeps its
 * ability to exit 0. What changes is that the number names what it is over.
 * Quick is measured-but-narrow — neither the `measured` nor the `unmeasured`
 * state `src/check/verdict.ts` represents — so the score is printed with its
 * denominator rather than withheld.
 */

import { CHECK_METHOD_PREFIXES } from '../hardening/coverage-ledger';
import { citationTarget } from './shell-quote';
import { CLI_PREFIX } from '../cli-prefix';

export interface CheckGroupTally {
  /** Check groups that returned without throwing. */
  ran: number;
  /** Every registered check group, run or not. */
  registered: number;
}

/**
 * How many check groups ran, out of the REGISTERED set. The Checks line and the
 * score line both read this, so the two denominators cannot disagree.
 *
 * Sized from `CHECK_METHOD_PREFIXES`, not `executions.length`: a group with no
 * execution record would otherwise vanish from both halves and the ratio could
 * only ever read `N of N`.
 */
export function checkGroupTally(executions: readonly { completed: boolean }[]): CheckGroupTally {
  return {
    ran: executions.filter(e => e.completed).length,
    registered: Object.keys(CHECK_METHOD_PREFIXES).length,
  };
}

export interface ScanDepthDisclosure {
  /** Appended to the score line, after the meter. Uncolored. */
  scoreSuffix: string;
  /** The line under the score naming the command that measures the rest. Uncolored. */
  followup?: string;
}

/**
 * The score-line denominator for a quick-depth run, or `null` when the score is
 * over the depth the user did not narrow (`standard`, `deep`, or a caller that
 * does not pass a depth) or when nothing was skipped.
 */
export function scanDepthDisclosure(opts: {
  scanDepth?: string;
  executions?: readonly { completed: boolean }[];
  /** Directory as the user typed it, for the follow-up command. */
  target?: string;
  /**
   * `--static-only`: the semantic layer did not run. A quick run with it and
   * one without it can score the same tree differently, and the two score
   * lines carried the same suffix; only the Checks line (`0 semantic`)
   * differed.
   */
  staticOnly?: boolean;
}): ScanDepthDisclosure | null {
  if (opts.scanDepth !== 'quick' || !opts.executions) return null;
  const { ran, registered } = checkGroupTally(opts.executions);
  if (ran >= registered) return null;
  const semantic = opts.staticOnly ? ', semantic layer off' : '';
  return {
    scoreSuffix: `  (over ${ran} of ${registered} check groups${semantic} — scan depth quick)`,
    // With the CLI prefix, like every other command the report cites: a bare
    // `secure <dir>` pasted into a shell is `command not found`.
    followup:
      opts.target !== undefined
        ? `Run \`${CLI_PREFIX} secure ${citationTarget(opts.target)}\` for the standard-depth score.`
        : undefined,
  };
}
