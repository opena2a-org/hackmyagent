/**
 * `fs/promises` namespace with read attribution for the coverage ledger.
 *
 * The scanner reads the target through 153 separate `fs.readFile` call sites
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
import { noteRead, noteInspect } from './coverage-ledger';

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
 */
function attribute<T extends AnyFn>(fn: T, report: (target: unknown) => void): T {
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
  if (typeof fn === 'function') wrapped[name] = attribute(fn as AnyFn, noteRead);
}

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

export default fs;
