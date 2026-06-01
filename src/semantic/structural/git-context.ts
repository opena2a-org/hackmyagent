/**
 * Git Context Helper (#208: gitignored .env severity downgrade)
 *
 * Provides a memoized per-rootDir view over `git ls-files`, `git log`, and
 * `git check-ignore` so structural analyzers can downgrade severity on
 * credentials that are gitignored AND never tracked.
 *
 * Calls return false on any error (missing git, non-zero exit, ENOENT). The
 * "safe default" for callers is to treat a non-git-repo as HIGH severity per
 * the #208 triage.
 *
 * Order matters when interpreting results:
 *   1. `hasFileInIndex`: currently tracked
 *   2. `hasFileInHistory`: added in ANY ref (--all + --reflog + --diff-filter=A)
 *   3. `isGitignored`: only meaningful if the file is NOT tracked
 *
 * A tracked file can match a gitignore pattern (gitignore does not untrack),
 * so a severity downgrade based on `isGitignored` alone would weaken
 * detection. Callers MUST check index + history BEFORE acting on
 * `isGitignored`.
 */

import { spawnSync } from 'node:child_process';
import { lstatSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import * as path from 'node:path';

export interface GitContext {
  rootDir: string;
  isGitRepo: boolean;
  hasFileInIndex(relPath: string): boolean;
  /**
   * Returns true if the path has EVER been added in any ref reachable from
   * --all OR appears in the reflog (covers deleted branches, `git reset
   * --hard`, dropped stashes within the default 90-day reflog window).
   * Does NOT cover dangling blobs after reflog expiry but before gc prune.
   * A non-empty hit here MUST block any severity downgrade.
   */
  hasFileInHistory(relPath: string): boolean;
  isGitignored(relPath: string): boolean;
  /**
   * Returns the list of in-tree candidate paths for relPath. For a regular
   * file this is `[relPath]`. For a symlink it includes the literal
   * readlink target plus the fully-resolved realpath, both expressed
   * relative to a realpath'd rootDir so a path.relative call never crosses
   * the repo boundary erroneously. Out-of-tree candidates are dropped.
   *
   * Returns `{ candidates, outOfTree, hardlinked }`:
   *   - `outOfTree: true` means at least one resolved candidate was
   *     outside the rootDir (e.g. symlink to /etc/secrets). Caller MUST
   *     treat that as "could be tracked somewhere we can't verify" and
   *     keep HIGH.
   *   - `hardlinked: true` means lstat reports nlink > 1 (file has at
   *     least one other path pointing at the same inode). Caller MUST
   *     keep HIGH.
   */
  resolveCandidates(relPath: string): { candidates: string[]; outOfTree: boolean; hardlinked: boolean };
}

interface GitResult {
  ok: boolean;
  stdout: string;
}

function runGit(rootDir: string, args: string[]): GitResult {
  try {
    const result = spawnSync('git', args, {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf-8',
      timeout: 5000,
    });
    if (result.error || result.status === null) return { ok: false, stdout: '' };
    return { ok: result.status === 0, stdout: result.stdout ?? '' };
  } catch {
    return { ok: false, stdout: '' };
  }
}

/**
 * Build a fresh GitContext for a single scan invocation.
 *
 * No module-level memoization: long-running consumers (MCP server) reuse
 * the same StructuralAnalyzer across calls. Caching across calls would
 * report stale tracking state for a path whose git status changed between
 * scans (e.g. user committed the previously-gitignored .env). Intra-scan
 * memoization is preserved via the per-instance Maps below.
 *
 * rootDir is realpath'd before anything else so candidate paths produced
 * by `path.relative(abs, realpathSync(symlinkTarget))` land inside the
 * repo on platforms where the working-tree path is itself a symlink
 * (macOS `/var/folders` -> `/private/var/folders`, NFS mounts, container
 * bind mounts).
 */
export function getGitContext(rootDir: string): GitContext {
  let abs: string;
  try {
    abs = realpathSync(path.resolve(rootDir));
  } catch {
    abs = path.resolve(rootDir);
  }

  const isGitRepo =
    runGit(abs, ['rev-parse', '--is-inside-work-tree']).stdout.trim() === 'true';

  const indexCache = new Map<string, boolean>();
  const historyCache = new Map<string, boolean>();
  const ignoreCache = new Map<string, boolean>();
  const candidateCache = new Map<string, { candidates: string[]; outOfTree: boolean; hardlinked: boolean }>();

  const ctx: GitContext = {
    rootDir: abs,
    isGitRepo,
    hasFileInIndex(relPath) {
      if (!isGitRepo) return false;
      const c = indexCache.get(relPath);
      if (c !== undefined) return c;
      const r = runGit(abs, ['ls-files', '--error-unmatch', '--', relPath]);
      indexCache.set(relPath, r.ok);
      return r.ok;
    },
    hasFileInHistory(relPath) {
      if (!isGitRepo) return false;
      const c = historyCache.get(relPath);
      if (c !== undefined) return c;
      // --all covers reachable refs; --reflog widens to deleted branches,
      // dropped stashes, and `git reset --hard` survivors so a downgrade
      // is not granted on a path that is only one `git fsck --lost-found`
      // away from re-exposing the secret.
      const r = runGit(abs, [
        'log',
        '--all',
        '--reflog',
        '--diff-filter=A',
        '--format=%H',
        '--',
        relPath,
      ]);
      const hit = r.ok && r.stdout.trim().length > 0;
      historyCache.set(relPath, hit);
      return hit;
    },
    isGitignored(relPath) {
      if (!isGitRepo) return false;
      const c = ignoreCache.get(relPath);
      if (c !== undefined) return c;
      const r = runGit(abs, ['check-ignore', '-q', '--', relPath]);
      ignoreCache.set(relPath, r.ok);
      return r.ok;
    },
    resolveCandidates(relPath) {
      const c = candidateCache.get(relPath);
      if (c !== undefined) return c;

      const candidates: string[] = [relPath];
      let outOfTree = false;
      let hardlinked = false;

      const pushIfInTree = (absTarget: string): void => {
        let resolved = absTarget;
        try {
          resolved = realpathSync(absTarget);
        } catch {
          // unreadable target; fall back to the literal path
        }
        const rel = path.relative(abs, resolved);
        if (rel.length === 0) return;
        // path.relative produces a leading `..` segment when the target
        // escapes abs. On POSIX that's `../`; on Windows it can be a
        // different drive letter (path.isAbsolute returns true). Either
        // way it's out-of-tree as far as `git ls-files` is concerned.
        if (rel.startsWith('..' + path.sep) || rel === '..' || path.isAbsolute(rel)) {
          outOfTree = true;
          return;
        }
        if (!candidates.includes(rel)) candidates.push(rel);
      };

      try {
        const absPath = path.resolve(abs, relPath);
        const st = lstatSync(absPath);

        if (st.isSymbolicLink()) {
          // Literal readlink (covers one hop, both relative + absolute
          // link form). Even if realpathSync below resolves the chain,
          // keeping the literal hop lets us match intermediate symlinks
          // that are themselves tracked.
          try {
            const linkRaw = readlinkSync(absPath);
            const linkAbs = path.isAbsolute(linkRaw)
              ? linkRaw
              : path.resolve(path.dirname(absPath), linkRaw);
            pushIfInTree(linkAbs);
          } catch {
            // ignore unreadable link
          }
          // Realpath walks the full chain; captures multi-hop chains.
          try {
            const real = realpathSync(absPath);
            pushIfInTree(real);
          } catch {
            // ignore broken realpath
          }
        } else {
          // Hardlink defense: a regular file with nlink > 1 shares its
          // inode with another path. We don't know that other path's git
          // state without scanning the whole tree; flag and let the
          // caller treat as HIGH.
          try {
            const realSt = statSync(absPath);
            if (realSt.nlink > 1) hardlinked = true;
          } catch {
            // ignore
          }
        }
      } catch {
        // lstat failed (broken symlink, missing file); fall through with
        // just the original path.
      }

      const result = { candidates, outOfTree, hardlinked };
      candidateCache.set(relPath, result);
      return result;
    },
  };

  return ctx;
}
