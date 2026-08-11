/**
 * `fs/promises` namespace with read attribution for the coverage ledger.
 *
 * The scanner reads the target through 151 separate `fs.readFile` call sites
 * plus a spread of `stat` / `readdir` / `access` calls. Instrumenting each one
 * would be fail-OPEN: a site missed in the sweep would let its check claim
 * coverage it never had, which is the exact defect the ledger exists to fix.
 *
 * So the namespace is wrapped once, here, and `scanner.ts` imports this
 * instead of `fs/promises`. Every existing call site is attributed with no
 * edit, and any call site added later is attributed automatically.
 *
 * Only the read-shaped calls report. Writes are not coverage evidence, and
 * they pass through untouched. Attribution itself is filtered by the active
 * ledger: a read outside the scan target is not evidence about the target.
 */

import * as realFs from 'fs/promises';
import { noteRead, noteInspect, noteReadFailure } from './coverage-ledger';

/**
 * Calls whose first argument is a path the scanner READ THE CONTENTS of.
 * These are the strongest form of evidence: the check saw the bytes.
 */
const CONTENT_READS = ['readFile'] as const;

/**
 * Calls that inspect a path without reading its contents. Weaker evidence,
 * but still evidence: a permissions check that `stat`s a file examined it,
 * even though it never opened it.
 */
const PATH_INSPECTIONS = [
  'readdir', 'stat', 'lstat', 'access', 'realpath', 'readlink', 'opendir',
] as const;

type AnyFn = (...args: unknown[]) => unknown;

/**
 * Wrap one namespace member so a SUCCESSFUL call reports what it touched.
 *
 * Attribution happens on resolve, never on call. The scanner probes for files
 * that usually do not exist — `.env.production`, `compose.yaml`, a dozen
 * config spellings per check — and counting those probes inflates the
 * coverage number with paths that hold nothing. Measured on a 529-file tree,
 * report-on-call gave `549 files examined`: more files than the tree contains,
 * a number that cannot be true and that overstates coverage, which is the one
 * direction this ledger must never be wrong in.
 *
 * A failed read is therefore not evidence. There was nothing there to examine.
 *
 * That sentence is true for `ENOENT` and false for everything else, and the
 * difference was #438. A file at mode 000 inside the target was discovered, was
 * probed, and its bytes never reached a check — but because the rejection was
 * rethrown and recorded nowhere, the file simply left the assessment, and
 * `secure` scored the tree 98/100 at exit 0 where the same tree with the same
 * file readable scored 69/100 at exit 1. The score went UP because the evidence
 * went away.
 *
 * So a failed read now reports too, on its own channel. `onFailure` records the
 * errno and the ledger decides which codes mean "discovered but not read"
 * (`unreadableInputs` drops `ENOENT`). Recording on the rejection cannot
 * overstate coverage the way report-on-call did: these paths never enter
 * `filesReadAll`, and `filesExamined` is unchanged by this wrapper.
 */
function attribute<T extends AnyFn>(
  fn: T,
  report: (target: unknown) => void,
  onFailure?: (target: unknown, code: unknown) => void,
): T {
  return function (this: unknown, ...args: unknown[]) {
    const target = args[0];
    const out = fn.apply(this, args) as Promise<unknown>;
    if (out && typeof (out as Promise<unknown>).then === 'function') {
      return out.then(
        (value) => {
          report(target);
          return value;
        },
        (err) => {
          // Rethrown unchanged: every existing call site's error handling is
          // untouched, and this wrapper stays invisible to control flow.
          onFailure?.(target, (err as NodeJS.ErrnoException | null)?.code);
          throw err;
        },
      );
    }
    // Non-thenable return (no such member in `fs/promises` today, but the
    // wrapper must not swallow one if a future Node adds it).
    report(target);
    return out;
  } as unknown as T;
}

const wrapped: Record<string, unknown> = { ...realFs };

for (const name of CONTENT_READS) {
  const fn = (realFs as unknown as Record<string, unknown>)[name];
  if (typeof fn === 'function') wrapped[name] = attribute(fn as AnyFn, noteRead, noteReadFailure);
}

// Failures are NOT reported on this channel. `access` is an existence probe by
// definition and `stat` is used the same way, so their rejections are the
// normal case rather than a lost input. An unreadable DIRECTORY is already
// caught where it matters: `scanner.ts` catches the `readdir` rejection, sets
// `complete = false` and emits a HIGH. Reporting it here as well would count
// one obstruction twice, in two units.
for (const name of PATH_INSPECTIONS) {
  const fn = (realFs as unknown as Record<string, unknown>)[name];
  if (typeof fn === 'function') wrapped[name] = attribute(fn as AnyFn, noteInspect);
}

/**
 * Drop-in replacement for `import * as fs from 'fs/promises'`.
 *
 * Typed as the real namespace so the scanner's existing call sites keep their
 * signatures and `tsc` still checks them.
 */
export const fs = wrapped as unknown as typeof realFs;

/**
 * There is deliberately NO tracked `readFileSync` here.
 *
 * A sync channel was built for #499 and then removed, because the sweep found
 * no consumer for it: the only sync reads of the target on the scan path are
 * citation re-reads of files already discovered and already attempted
 * (`scanner-bridge.ts` `readArtifact`, `scanner.ts` `readArtifactForCitation`),
 * and those must NOT report. `unreadableInputs` subtracts a failure only when
 * the same method later reads that path successfully, so a re-read failing on a
 * path another check had read would be an unsubtractable false unread input.
 *
 * If a genuine sync DISCOVERY read of the target ever appears, add the channel
 * back — the wrapper shape above is the template. Do not route a re-read
 * through it.
 */

export default fs;
