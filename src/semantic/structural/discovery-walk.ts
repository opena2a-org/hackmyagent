/**
 * Bounded, symlink-safe discovery of Layer-2 artifacts BELOW the scan root.
 *
 * #298 — `FILE_DISCOVERY` was a fixed root-relative probe list and the walk was
 * `path.join(targetDir, glob)`, so all four structural analyzers
 * (`CredentialContextAnalyzer`, `McpConfigAnalyzer`, `InstructionAnalyzer`,
 * `PermissionModelAnalyzer`) were blind to their own artifact one directory
 * down. Measured on `22010af`, byte-identical content, only the placement
 * changing:
 *
 *   root/    -> score 35, 5 SEM findings (CRED-004, INST-001, INST-002,
 *                                         PERM-001, PERM-002)
 *   nested/  -> score 69, 0 SEM findings
 *
 * (The issue says the user-visible verdict is "now correct at any depth"
 * because #292 fixed the CRED-001 half. It is not: 35 vs 69 on the same bytes.)
 *
 * This is the same root cause as #292, which fixed it for ONE layer-1 check.
 * The shape here deliberately mirrors that fix (`scanner.ts:2880`): the root
 * probe runs first and UNCONDITIONALLY, the walk's extra locations are appended
 * after it in sorted order, and the walk may only ever ADD locations, never
 * subtract them — so a deep or unreadable directory can never remove detection
 * that exists today, and root-only trees (every pre-existing corpus fixture)
 * produce byte-identical output.
 *
 * Containment reuses `src/hardening/contain.ts` rather than adding a third
 * implementation of "is this path inside the tree" — the asymmetry between two
 * such implementations is what #270/#318 were.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { FileType } from '../types';
import { isPathWithinDirectory } from '../../hardening/contain';

/** One entry of the discovery list: a root-relative path suffix and its type. */
export interface ArtifactSpec {
  glob: string;
  type: FileType;
}

/** An artifact found by the walk, as a path relative to the scan root. */
export interface WalkedArtifact {
  rel: string;
  type: FileType;
}

export interface WalkResult {
  artifacts: WalkedArtifact[];
  /**
   * False when the walk could NOT see the whole tree — an unreadable
   * directory, or a bound reached. Absence is only trustworthy when this is
   * true.
   *
   * No Layer-2 finding is absence-based across the tree: every one is derived
   * from the CONTENT of a file that was read (verified across all four
   * analyzers, 2026-08-03). So an incomplete walk under-reports, which is the
   * direction the root-only code already failed in, and can never turn an
   * unreadable directory into a positive accusation.
   */
  complete: boolean;
}

export interface WalkOptions {
  /**
   * Directories the caller has already accounted for and must not be read
   * again.
   *
   * This exists for exactly one caller and one directory: `--fix` creates
   * `.hackmyagent-backup/<stamp>/` (`scanner.ts:1827`) BEFORE Layer 2 runs
   * (`scanner.ts:2105`), and it holds verbatim copies of `CLAUDE.md`,
   * `config.json` and `.claude/settings.json`. Walking into it reports every
   * semantic finding twice — once for the live file, once for its own backup —
   * which is #302's harm arriving in the semantic layer.
   *
   * It is a PREDICATE, not a name. `.hackmyagent-backup` as a string is a
   * suppression token the scanned tree can plant (#305/#309); the scanner
   * passes `isOwnBackupDir`, which decides by `dev`+`ino` identity and so
   * excludes THIS RUN's backup and nothing else. A pre-existing archive holds
   * a real plaintext secret and is still reported — the same policy Layer 1
   * settled on.
   */
  isExcludedDir?: (absDir: string) => Promise<boolean>;
}

/** Match layer 1's bounds (`collectSensitiveArtifacts`): generous, so real repositories walk to completion. */
const MAX_DEPTH = 25;
const MAX_ENTRIES = 50000;

/**
 * Cap on artifacts the walk will hand back.
 *
 * Layer 1's walk collects PATHS; this one's results get READ, and each
 * `AnalysisFile` holds up to 512KB of content in memory and is additionally
 * shipped to the Layer-3 LLM analyzer. Uncapped, a tree with thousands of
 * `config.json` files turns a scan into an OOM and a metered API bill. 500 is
 * far above any real repository's count of agent-config artifacts.
 */
const MAX_ARTIFACTS = 500;

/**
 * A path suffix match on SEGMENT boundaries, most-specific first.
 *
 * Basename alone is ambiguous and would mistype: `sub/.claude/settings.json`
 * matches both `.claude/settings.json` (claude_settings) and `settings.json`
 * (config_file), and only the first routes it to `PermissionModelAnalyzer`.
 * The most path segments wins, so the specific location beats the generic
 * name. `.env` does not match `sub/.env.local`, and `sub/x.env` matches
 * nothing, because the comparison is anchored at a separator.
 */
export function classifyArtifact(
  rel: string,
  specs: readonly ArtifactSpec[],
): FileType | undefined {
  const posix = rel.split(path.sep).join('/');
  let best: ArtifactSpec | undefined;
  let bestSegments = -1;
  for (const spec of specs) {
    const glob = spec.glob.split(path.sep).join('/');
    if (posix !== glob && !posix.endsWith(`/${glob}`)) continue;
    const segments = glob.split('/').length;
    // Strictly greater keeps the FIRST spec of equal specificity, so the
    // discovery list's own order remains the tie-break and the result does not
    // depend on how the list happens to be sorted.
    if (segments > bestSegments) {
      best = spec;
      bestSegments = segments;
    }
  }
  return best?.type;
}

/**
 * Walk `targetDir` for anything matching `specs`, at any depth.
 *
 * Symlink handling is layer 1's, because it is the version that survived
 * #318/#327's review: symlinked dirents are skipped outright (HMA never
 * follows a link out of the scanned tree), every entry is re-`lstat`ed before
 * descending so a directory swapped for a link between `readdir` and the
 * recursive call cannot redirect the walk, and the joined path is asserted to
 * be inside the root even though `readdir` only ever yields single-component
 * names.
 */
export async function walkForArtifacts(
  targetDir: string,
  specs: readonly ArtifactSpec[],
  opts: WalkOptions = {},
): Promise<WalkResult> {
  const artifacts: WalkedArtifact[] = [];
  let entries = 0;
  let complete = true;

  try {
    const rootStat = await fs.stat(targetDir);
    // A single-FILE target has no tree to walk; the caller handles it, and an
    // empty result there is complete rather than unverifiable.
    if (!rootStat.isDirectory()) return { artifacts, complete: true };
  } catch {
    return { artifacts, complete: true };
  }

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (entries >= MAX_ENTRIES || artifacts.length >= MAX_ARTIFACTS) {
      complete = false;
      return;
    }
    let dirents;
    try {
      dirents = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      // EACCES and friends: a config we cannot see could be in there, so this
      // result is not a proof of absence.
      complete = false;
      return;
    }
    for (const dirent of dirents) {
      if (entries++ >= MAX_ENTRIES) {
        complete = false;
        return;
      }
      if (dirent.isSymbolicLink()) continue;
      const abs = path.join(dir, dirent.name);
      // Belt-and-suspenders: `readdir` never yields `..` or an absolute name,
      // so this holds by construction. Kept so no read ever touches a path
      // outside the scan root even if that invariant were violated.
      if (!isPathWithinDirectory(abs, targetDir)) {
        complete = false;
        continue;
      }

      if (dirent.isDirectory()) {
        // `.git` holds no agent config and is never committable as one.
        // `node_modules` is a dependency-review problem with its own checks,
        // and reading every vendored `config.json` is what makes this walk
        // unaffordable. Both are policy skips, not failures to look, so
        // neither costs completeness — the same stance layer 1 takes.
        if (dirent.name === '.git' || dirent.name === 'node_modules') continue;
        if (depth + 1 > MAX_DEPTH) {
          complete = false;
          continue;
        }
        // TOCTOU: re-examine before descending.
        try {
          const st = await fs.lstat(abs);
          if (!st.isDirectory()) continue;
        } catch {
          complete = false;
          continue;
        }
        if (opts.isExcludedDir && (await opts.isExcludedDir(abs))) continue;
        await walk(abs, depth + 1);
        if (artifacts.length >= MAX_ARTIFACTS) return;
        continue;
      }

      if (!dirent.isFile()) continue;
      const rel = path.relative(targetDir, abs);
      const type = classifyArtifact(rel, specs);
      if (type === undefined) continue;
      if (artifacts.length >= MAX_ARTIFACTS) {
        complete = false;
        return;
      }
      artifacts.push({ rel, type });
    }
  };

  await walk(targetDir, 0);

  // `readdir` order is filesystem-dependent and the corpus goldens are
  // byte-compared, so an unsorted list would make golden stability a property
  // of the host filesystem.
  artifacts.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));

  return { artifacts, complete };
}
