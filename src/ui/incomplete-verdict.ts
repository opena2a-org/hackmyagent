/**
 * #568 — the Verdict line over a tree holding an input the run could not read.
 *
 * `secure` and `check` share `displayUnifiedCheck`. Over such a tree the exit
 * code is 2 and the score is an upper bound, but the Verdict line opened with
 * the band sentence (`Usable with caveats. Dependency Lock File in ...`) and
 * the reason the run did not conclude sat in the findings far below. The line
 * a reader anchors on now leads with the incompleteness, naming the first
 * unread path and its errno, and the band sentence follows it unchanged.
 *
 * Only the order moves. The score, the exit code, the findings and `--json`
 * are untouched, and a fail-direction band keeps its own lead: `Not safe` is
 * already the stronger statement, so the caller skips this for `unsafe`.
 */

export interface UnreadFindingLike {
  checkId: string;
  file?: string;
  kind?: 'file' | 'directory';
  message?: string;
}

const UNREAD_CHECK_ID = 'SCAN-UNREAD-001';

/**
 * The errno the SCAN-UNREAD-001 message carries. The message is tool-authored
 * (`<path> could not be read (<CODE>)` or `<path> could not be listed (<CODE>)
 * — ...`), but its path came from the scanned tree, so the LAST match is the
 * one the tool wrote: a file named to contain the phrase cannot move it.
 */
function unreadErrno(message: string): string | undefined {
  const matches = [...message.matchAll(/could not be (?:read|listed) \(([A-Z][A-Z0-9_]*)\)/g)];
  return matches.length > 0 ? matches[matches.length - 1][1] : undefined;
}

/**
 * The clause to put in front of the Verdict, or `null` when every discovered
 * input was read. `unreadCount` is the measured count from the coverage
 * ledger; it is used when the findings do not name every unread input (for
 * example a `--ignore SCAN-UNREAD-001` run), so the count is never smaller
 * than what the run measured.
 */
export function incompleteVerdictLead(
  findings: readonly UnreadFindingLike[],
  unreadCount: number,
  displayPath: (p: string) => string,
): string | null {
  const unread = findings.filter((f) => f.checkId === UNREAD_CHECK_ID && f.file);
  const total = Math.max(unreadCount, unread.length);
  if (total === 0) return null;
  const upperBound = 'The score is an upper bound over what was read.';
  const first = unread[0];
  if (!first) {
    return `Incomplete: ${total} input${total === 1 ? '' : 's'} could not be read. ${upperBound}`;
  }
  const verb = first.kind === 'directory' ? 'listed' : 'read';
  const code = unreadErrno(first.message ?? '');
  const more = total - 1;
  return `Incomplete: ${displayPath(first.file as string)} could not be ${verb}${code ? ` (${code})` : ''}`
    + (more > 0 ? `, and ${more} more input${more === 1 ? ' was' : 's were'} not read` : '')
    + `. ${upperBound}`;
}
