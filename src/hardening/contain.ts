/**
 * Path containment for every path HMA is about to ACT on.
 *
 * This started as one private method inside `HardeningScanner`, built for the
 * rollback side by #318/#327. It is a module because the write side needs the
 * identical property and had none: `rollback` refused to restore through a link
 * that leaves the scanned tree while `--fix` followed one anywhere and rewrote
 * the file at the far end (#270). Two implementations of "is this path inside
 * the tree" is how that asymmetry arose in the first place, so there is one.
 */

import * as path from 'path';
import { promises as fs, realpathSync } from 'fs';

/**
 * Site-level read confinement for the few raw-`fs` readers that bypass the
 * tracked namespace by design (`readArtifactForCitation`, the NanoMind
 * bridge's policy probe and citation re-read, the CLI's single-file copy).
 *
 * Same decision as the namespace guard in `tracked-fs.ts`, on the same
 * predicate: the read is refused when `filePath` really resolves outside
 * `realpath(treeRoot)`. The lexical form of `filePath` is NOT checked here —
 * every caller has already joined its name onto the tree, and the guard's
 * "lexically inside" test is about which paths the tree can redirect, which
 * at these sites is all of them. Both sides are resolved before comparing, so
 * a target under a symlinked ancestor (`/var` -> `/private/var`) stays inside.
 *
 * `{ ok: true }` when either side cannot be resolved: an unresolvable path is
 * the caller's own errno to report, and refusing on a claim the filesystem
 * would not confirm would mask a genuine lost input.
 */
export function readStaysInsideTree(
  filePath: string,
  treeRoot: string,
): { ok: true } | { ok: false; resolved: string } {
  let real: string;
  let rootReal: string;
  try {
    real = realpathSync(filePath);
    rootReal = realpathSync(treeRoot);
  } catch {
    return { ok: true };
  }
  return isPathWithinDirectory(real, rootReal) ? { ok: true } : { ok: false, resolved: real };
}

/**
 * Why `resolveInsideTree` would not hand back a path to act on.
 *
 * #347.4 — one sentence used to be printed for every one of these. "Its
 * destination does not resolve to a location inside the scanned directory" was
 * shown for a dangling symlink, for an EACCES on the parent, and for a `..`:
 * three causes, and it is true of one of them. A user who reads it about an
 * EACCES goes looking for a traversal that is not there.
 *
 * The refusals are the same as before — this names them.
 */
export type ResolveRefusal =
  | 'escapes-tree'
  | 'parent-unresolvable'
  | 'parent-outside-tree'
  | 'leaf-is-link'
  | 'leaf-link-dangling'
  | 'leaf-link-outside-tree'
  | 'leaf-unexaminable';

export type ResolveOutcome =
  | { ok: true; path: string }
  | { ok: false; cause: ResolveRefusal };

/** Lexical containment. Sound as a NEGATIVE only; a symlink defeats it. */
export function isPathWithinDirectory(filePath: string, directory: string): boolean {
  const normalizedFile = path.resolve(filePath);
  const normalizedDir = path.resolve(directory);
  return normalizedFile.startsWith(normalizedDir + path.sep) || normalizedFile === normalizedDir;
}

/**
 * Resolve `rel` against `targetReal` to a real location inside the tree, or
 * say why it does not stay there.
 *
 * `rel` is attacker data in the rollback case (it comes out of a manifest in
 * the scanned tree, #312) and target-derived in the write case. A lexical
 * containment check on the JOINED path is not enough (#318): it decides where
 * the string points, not where the filesystem sends it, and a symlinked
 * directory component sends it anywhere. So:
 *
 *   - the `..` cases are refused first, with no syscall spent on them;
 *   - the destination's PARENT is resolved and required to be inside the tree,
 *     which is what catches a symlinked component;
 *   - the LEAF is handled per caller, because the callers ask different
 *     questions. See `followLeafLink`.
 *
 * #327 — the leaf used to be refused outright whenever it was a symlink, for
 * every caller. That broke an ordinary dotfile-sharing layout with no attacker
 * involved: `--fix` writes THROUGH a symlinked config, so the file was backed
 * up and redacted and then could not be restored. Refusing to follow on the way
 * back what was followed on the way in is not a containment property, it is an
 * asymmetry.
 *
 *   - `followLeafLink: true` (fix write, restore) resolves the link and
 *     requires the TARGET to be inside the tree. An out-of-tree target is
 *     refused — that is #318's harm on the restore side and #270's on the write
 *     side — and the returned path is the resolved one, so the bytes land where
 *     the check looked.
 *   - `followLeafLink: false` (unlink, probe) keeps the refusal. HMA never
 *     CREATES a symlink, so a link standing where a generated file should be is
 *     not the thing HMA generated, and deleting what it points at would be #318
 *     with the arrow reversed.
 *
 * Returns the path to ACT on — never the caller's spelling. Three separate
 * resolutions of one string (`realpath` here, then `lstat`/`copyFile`/`writeFile`
 * at the call site) are not atomic against a tree changing underneath them; that
 * is outside the static-tree threat model the rest of this code assumes, and
 * only a descriptor (`open` + `fstat`) would close it.
 */
export async function resolveInsideTree(
  targetReal: string,
  rel: string,
  opts: { followLeafLink: boolean },
): Promise<ResolveOutcome> {
  const joined = path.join(targetReal, rel);
  if (!isPathWithinDirectory(joined, targetReal)) {
    return { ok: false, cause: 'escapes-tree' };
  }

  let parentReal: string;
  try {
    parentReal = await fs.realpath(path.dirname(joined));
  } catch {
    // parent gone: nothing to restore into, nothing to delete, nowhere to write
    return { ok: false, cause: 'parent-unresolvable' };
  }
  if (!isPathWithinDirectory(parentReal, targetReal)) {
    return { ok: false, cause: 'parent-outside-tree' };
  }

  const resolved = path.join(parentReal, path.basename(joined));
  try {
    const st = await fs.lstat(resolved);
    if (st.isSymbolicLink()) {
      if (!opts.followLeafLink) return { ok: false, cause: 'leaf-is-link' };
      // Where the link actually goes, decided by the filesystem. A dangling
      // link resolves to nothing and is refused: there is nothing to restore
      // through it, and a fix write through it would create a file at a
      // location this check never got to examine.
      let linkReal: string;
      try {
        linkReal = await fs.realpath(resolved);
      } catch {
        return { ok: false, cause: 'leaf-link-dangling' };
      }
      return isPathWithinDirectory(linkReal, targetReal)
        ? { ok: true, path: linkReal }
        : { ok: false, cause: 'leaf-link-outside-tree' };
    }
  } catch (err) {
    // ENOENT is the only failure that PROVES the leaf is not a symlink:
    // nothing is there. Absence is expected and fine — restoring a file the
    // user deleted is the point, and a fix write that creates a new file is
    // the other legitimate case.
    //
    // Any other errno (EACCES on the parent, ELOOP, EIO) proves nothing, and
    // "I could not check whether this is a symlink" must not become "it is
    // not one" — that is #313's inference in a new place. Refuse instead: the
    // entry is reported as not restored / not written, which is recoverable.
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      return { ok: false, cause: 'leaf-unexaminable' };
    }
  }
  return { ok: true, path: resolved };
}

/**
 * One sentence per refusal, for a user who has to decide what to do next.
 *
 * Kept beside the causes so a new refusal cannot be added without a sentence —
 * #347.4 was one sentence covering seven causes, true of one of them.
 */
export function describeResolveRefusal(cause: ResolveRefusal): string {
  switch (cause) {
    case 'escapes-tree':
      return 'its path points outside the scanned directory';
    case 'parent-unresolvable':
      return 'the directory that would contain it could not be resolved';
    case 'parent-outside-tree':
      return 'a directory above it is a link that leaves the scanned directory';
    case 'leaf-is-link':
      return 'a symbolic link stands where the file should be, and HackMyAgent never creates one';
    case 'leaf-link-dangling':
      return 'it is a symbolic link that points at nothing';
    case 'leaf-link-outside-tree':
      return 'it is a symbolic link that points outside the scanned directory';
    case 'leaf-unexaminable':
      return 'the filesystem would not say what it is';
  }
}
