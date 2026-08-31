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
import { fileURLToPath } from 'url';
import { join } from 'path';
import { noteRead, noteInspect, noteReadFailure, noteListFailure, noteListed, withholdOutOfTree } from './coverage-ledger';

/**
 * Out-of-tree link confinement, enforced ONCE for every namespace caller.
 *
 * The scanner joins a basename onto the target and reads it from ~150 sites
 * in 40-plus methods, and its walkers skip symlinked ENTRIES but follow a
 * directory link handed in as the walk root. A link at any of those names
 * (`.env -> ~/.aws/credentials`, `skills -> /`) is a path any contributor can
 * commit, and every one of those sites followed it: measured on a five-link
 * fixture, a plain `secure` made 58 link-following calls that reached an
 * out-of-tree realpath from 23 distinct call frames, and the bytes reached
 * findings, `--output`, and (under `--deep`) the Layer-3 request body.
 * Instrumenting the sites would be fail-open for the reason the header above
 * gives for attribution, so the guard sits here, on the same wrap.
 *
 * Before delegating a link-following member, the first argument is normalized
 * (string, Buffer, or file URL) and the active ledger is asked whether the
 * path is lexically inside a confinement root and really outside every root.
 * If so the call is refused with an ENOENT-shaped rejection — under the
 * invariant the tree holds a link, not the file, and every catch on the scan
 * path already reads ENOENT as "subject absent" — and the refusal is recorded
 * on the ledger's `withheldLinks` channel, which the report discloses and
 * which never counts as an unread input. `lstat` and `readlink` touch only
 * the link's own metadata, so they are refused only when the PARENT resolves
 * outside. `realpath` is the instrument and passes through. A path the
 * filesystem will not resolve falls through to the real call, so no genuine
 * lost input is masked. No ledger installed means no root set, and every call
 * passes through: the guard governs scans, and a scan always runs under one.
 */
const LINK_FOLLOWING = ['readFile', 'stat', 'access', 'readdir', 'opendir', 'open'] as const;
const PARENT_ONLY = ['lstat', 'readlink'] as const;

/** The path a namespace call names, or `null` for a descriptor or any other shape. */
function pathArgument(target: unknown): string | null {
  if (typeof target === 'string') return target;
  if (Buffer.isBuffer(target)) return target.toString();
  if (target instanceof URL) {
    try { return fileURLToPath(target); } catch { return null; }
  }
  return null;
}

/** An error every existing `catch` reads as "absent", carrying what the errno cannot say. */
function withheldError(call: string, target: string, resolved: string): NodeJS.ErrnoException {
  const err = new Error(
    `ENOENT: withheld, link resolves outside the scanned tree (${resolved}), ${call} '${target}'`,
  ) as NodeJS.ErrnoException;
  err.code = 'ENOENT';
  err.errno = -2;
  err.syscall = call;
  err.path = target;
  return err;
}

function confine<T extends AnyFn>(fn: T, call: string, parentOnly: boolean): T {
  return function (this: unknown, ...args: unknown[]) {
    const target = pathArgument(args[0]);
    if (target !== null) {
      const withheld = withholdOutOfTree(target, call, parentOnly);
      if (withheld) return Promise.reject(withheldError(call, target, withheld.resolved));
    }
    const out = fn.apply(this, args);
    if (call === 'readdir' && target !== null && out && typeof (out as Promise<unknown>).then === 'function') {
      return (out as Promise<unknown>).then((entries) => {
        discloseSymlinkEntries(target, entries);
        return entries;
      });
    }
    return out;
  } as unknown as T;
}

/**
 * Disclosure for the links the walkers never follow.
 *
 * The discovery walkers that skip a symlinked dirent do so on a
 * `withFileTypes` listing (`discovery-walk.ts:215`, the `isSymbolicLink()`
 * sites in `scanner.ts`), so a link one directory down is never the argument
 * of a link-following call and the guard above never sees it. (A walker that
 * `stat`s each listed name instead, as `assembly-scanner.ts` does, is refused
 * by the guard and recorded there.) Not following it is the right outcome;
 * not SAYING so is not — the invariant is "refused and disclosed", and a
 * reader comparing this tree with its twin is owed the same list either way.
 * So a successful listing asks the ledger about each symlinked entry, which
 * records the out-of-tree ones and follows nothing. One site, every walker.
 */
/**
 * Directory names no walker on the scan path ever enters. A listing-time
 * disclosure of a link at one of these names would tell the operator to
 * re-point the scan at a tree the scan would not read either way (a checkout
 * with a symlinked node_modules is the everyday case). A check that does read
 * through such a link is still refused by the guard above and disclosed there.
 */
const NEVER_WALKED = new Set(['.git', 'node_modules']);

function discloseSymlinkEntries(listed: string, entries: unknown): void {
  if (!Array.isArray(entries)) return;
  for (const entry of entries) {
    const dirent = entry as { name?: unknown; parentPath?: unknown; path?: unknown; isSymbolicLink?: () => boolean } | null;
    if (!dirent || typeof dirent.isSymbolicLink !== 'function' || typeof dirent.name !== 'string') continue;
    if (NEVER_WALKED.has(dirent.name)) continue;
    let isLink = false;
    try { isLink = dirent.isSymbolicLink(); } catch { continue; }
    if (!isLink) continue;
    // `parentPath` (Node 20.12+); `path` on the Node 18/20 line; the listed
    // directory for a non-recursive listing on either.
    const parent = typeof dirent.parentPath === 'string' ? dirent.parentPath
      : typeof dirent.path === 'string' ? dirent.path
      : listed;
    // Recorded as `listing`: nothing was refused here, the entry was seen and
    // not followed. First record wins, so a later refusal on the same link
    // keeps this label; the resolved target is the same either way.
    withholdOutOfTree(join(parent, dirent.name), 'listing', false);
  }
}

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
  'stat', 'lstat', 'access', 'realpath', 'readlink',
] as const;

/**
 * Calls that LIST a directory. Inspections for the success channel, and —
 * unlike the probes above — a rejection here is a lost input: a directory the
 * scan cannot list loses every path under it without a single read ever being
 * attempted, so nothing on the read channel can disclose it (#588).
 */
const DIRECTORY_LISTINGS = ['readdir', 'opendir'] as const;

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
          //
          // Attributed to the path the ERRNO names, not to the argument: a
          // recursive readdir rejects with the errno of a NESTED directory,
          // and recording the listable argument named the wrong directory,
          // printed a chmod that was a no-op, and let coalescing suppress the
          // true record (#588 adversarial round). For every plain call the
          // two are the same path; when the error carries none, the argument
          // stands.
          const errPath = (err as NodeJS.ErrnoException | null)?.path;
          onFailure?.(typeof errPath === 'string' && errPath.length > 0 ? errPath : target,
            (err as NodeJS.ErrnoException | null)?.code);
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
// definition and `stat` is mostly used the same way, so their rejections are
// the normal case rather than a lost input — at PROBE sites. A `stat` on a
// path a walker has already listed is a discovery read, and a rejection there
// IS a lost input: `chmod 600 <dir>` lists the directory's files and rejects
// every `stat` on them (#515). That case is recorded by the discovery site
// itself (`scanner-bridge.ts` `isWithinSizeLimit`), the only place that knows
// the path was discovered rather than probed; this wrapper cannot tell the two
// apart and must not guess.
for (const name of PATH_INSPECTIONS) {
  const fn = (realFs as unknown as Record<string, unknown>)[name];
  if (typeof fn === 'function') wrapped[name] = attribute(fn as AnyFn, noteInspect);
}

// A directory listing that fails IS reported (#588). `readdir` on a path that
// exists is never a probe in the `access` sense — the caller wants the
// contents, and a rejection means every path beneath it left the scan. The
// ledger applies the same NOT_THERE policy as for reads, so `readdir` on a
// missing or non-directory path (ENOENT/ENOTDIR — a probe for a config
// directory that is not there) stays free. The discovery walkers record the
// same rejection at their own catch sites; the ledger dedups by path, and the
// second record is what a test seam that replaces this namespace observes.
// A listing that succeeds is an inspection for the coverage counts AND a
// listing for the failure channel's subtraction rule — the two are reported
// separately because a `stat` succeeding on a directory is not a listing.
const noteInspectedAndListed = (target: unknown): void => {
  noteInspect(target);
  noteListed(target);
};
for (const name of DIRECTORY_LISTINGS) {
  const fn = (realFs as unknown as Record<string, unknown>)[name];
  if (typeof fn === 'function') wrapped[name] = attribute(fn as AnyFn, noteInspectedAndListed, noteListFailure);
}

// The confinement guard wraps OUTSIDE attribution, so a withheld call never
// reaches the attribution wrapper at all: it is neither a read the check saw
// nor a failure on the unread-input channel. It is a refusal, recorded on its
// own channel by the ledger that decided it.
for (const name of LINK_FOLLOWING) {
  const fn = wrapped[name];
  if (typeof fn === 'function') wrapped[name] = confine(fn as AnyFn, name, false);
}
for (const name of PARENT_ONLY) {
  const fn = wrapped[name];
  if (typeof fn === 'function') wrapped[name] = confine(fn as AnyFn, name, true);
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
