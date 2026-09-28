/**
 * Where the findings folded into a `+ N more <severity>` line live (#360).
 *
 * The default (non-verbose) report collapses findings that share a name and a
 * DIRECTORY into one line under the finding it printed. The line used to name
 * the printed finding's own file, so three `eval()` findings in `lib/a.js`,
 * `lib/b.js` and `lib/c.js` rendered as `+ 2 more critical in a.js`: a reader
 * opens `a.js`, finds one of the three, and concludes the tool is wrong or the
 * rest are already fixed. The location has to describe the findings that were
 * folded, not the one that was shown.
 *
 * Collapsed findings share the printed finding's directory, so a base name is
 * unambiguous here and is what the line has always shown.
 */
import { escapePathForDisplay } from './display-safe';

/** More distinct files than this are counted rather than listed. */
export const MAX_NAMED_FILES = 3;

/**
 * The ` in …` suffix for a collapse line, or `''` when no truthful location
 * can be given.
 *
 * `collapsedFiles` is the `file` of every folded finding, in report order. One
 * file: ` in a.js`. Up to {@link MAX_NAMED_FILES}: ` in b.js, c.js`. More: ` in
 * 5 files`. When any folded finding carries no file, the files that do cannot
 * stand for all of them, so no location is claimed and `--verbose` is the
 * route to the detail, as the line already says.
 */
export function collapsedLocation(collapsedFiles: ReadonlyArray<string | undefined>): string {
  if (collapsedFiles.length === 0) return '';
  const names: string[] = [];
  for (const file of collapsedFiles) {
    if (!file) return '';
    const name = file.split('/').pop() || file;
    if (!names.includes(name)) names.push(name);
  }
  if (names.length > MAX_NAMED_FILES) return ` in ${names.length} files`;
  return ` in ${names.map(escapePathForDisplay).join(', ')}`;
}
