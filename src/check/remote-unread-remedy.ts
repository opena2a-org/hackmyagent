/**
 * #508 — the remedy `SCAN-UNREAD-001` carries out of the scanner is written
 * for a tree on the user's machine: `chmod u+r <file> && secure <dir>`. On a
 * downloaded target both halves are wrong. The directory it cites is a temp
 * extraction the `finally` deletes before the user reads the line (and the
 * path leaked into `--json`), and `chmod` on a copy fixes nothing about the
 * artifact: for an npm / PyPI / URL archive the mode bits are part of the
 * archive, so an unreadable member is a property of what was published and
 * whoever published it chose it. The fix text is rewritten here, once, for
 * every remote arm; the finding, its severity and the exit code it settled
 * are untouched.
 *
 * Pure and exported so it can be tested without a network: no instrument
 * produces a real unreadable member of a published package on demand.
 */
import { reemitFinding, type RedactedFinding } from '../hardening/finding-emit';
import { escapePathForDisplay } from '../ui/display-safe';

export type RemoteTargetKind = 'repository' | 'package' | 'archive';

export const UNREAD_INPUT_CHECK_ID = 'SCAN-UNREAD-001';

export function remoteUnreadRemedy(
  kind: RemoteTargetKind,
  member: string | undefined,
  inspect: string | undefined,
): string {
  const named = member ? escapePathForDisplay(member) : 'a file';
  const origin = kind === 'repository'
    ? 'Git does not store a permission bit that denies reading, so the mode came from the checkout on this machine rather than from the repository; re-check the clone with ls -l.'
    : `Mode bits are part of the archive, so this is a property of the ${kind} — set by whoever published it, not by your machine. Treat the file as unreviewed.`;
  return `This ${kind} contains ${named} with permissions that make it unreadable after extraction, so it was not scanned. ${origin}${inspect ? ` Inspect the member list before depending on it: ${inspect}` : ''}`;
}

export function rewriteRemoteUnreadRemedy(
  findings: RedactedFinding[],
  kind: RemoteTargetKind,
  inspect: string | undefined,
): RedactedFinding[] {
  return findings.map((f) =>
    f.checkId === UNREAD_INPUT_CHECK_ID
      ? reemitFinding(f, { fix: remoteUnreadRemedy(kind, f.file, inspect) })
      : f,
  );
}
