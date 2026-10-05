/**
 * Change-scoped `secure` (#537): `--range <base>..<head>` and `--staged`.
 *
 * A tree scan answers "does this tree contain a problem?". A pull request
 * gate asks a different question — "does this CHANGE introduce one?" — and
 * a tree scan cannot answer it: on a repository with one known, unremediated
 * finding it fails every pull request, including the ones that touch nothing
 * related, and a check that is always red gets ignored.
 *
 * The change is answered by scanning both sides and subtracting:
 *
 *   1. git materializes the base tree and the head tree (a commit, or the
 *      index for `--staged`) into a private temp directory. The working tree
 *      and the repository's own index are never written.
 *   2. Both trees are scanned with the same options.
 *   3. A head finding is REPORTED only when no base finding has the same
 *      identity: check id, file (followed through renames), and the content
 *      of the cited line — or, for a finding that cites no line, its message.
 *      Matching is one-for-one, so a second copy of a pre-existing line is
 *      still introduced.
 *
 * Line numbers are deliberately not part of the identity: a change that
 * inserts lines above a pre-existing secret moves it without introducing it.
 * A file the change deletes is absent from the head tree, so it contributes
 * nothing. A finding whose cited line the change edits is reported: the
 * change wrote that line.
 *
 * This module reads with the raw `fs` namespace on purpose, and sits beside
 * `cli.ts` rather than under `hardening/` for the same reason: it produces the
 * trees the scanner reads (as `extract-archive.ts` does for `check`), and its
 * only reads of their content are re-reads of lines the scan already cited,
 * after the scan has finished. Those must not reach the coverage ledger — see
 * the note on sync reads at the end of `hardening/tracked-fs.ts`.
 */
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { usageError } from './checker/errors';

export type ChangeScopeRequest = { kind: 'range'; spec: string } | { kind: 'staged' };

export interface ChangeScope {
  mode: 'range' | 'staged';
  /** The range exactly as given (`--range`), or `null` for `--staged`. */
  range: string | null;
  /** The commit the change is measured against; `null` when it is the empty tree (an unborn branch under `--staged`). */
  baseCommit: string | null;
  /** The commit whose tree is scanned; `null` for `--staged`, where the index is scanned. */
  headCommit: string | null;
  /** Absolute path of the repository's top level. */
  repoRoot: string;
  /** The scan target's path inside the repository, `/`-separated, empty or ending in `/`. */
  prefix: string;
  /** Base path -> head path for every file the change renames (repository-relative). */
  renames: Map<string, string>;
  /** Tree-ish git reads for each side. */
  baseTree: string;
  headTree: string | null;
}

export interface ParsedRange {
  base: string;
  head: string;
  /** `A...B`: measured from the merge base of A and B, as a pull request diff is. */
  mergeBase: boolean;
}

/**
 * `A..B`, `A...B`, and `A..` / `A...` (head defaults to `HEAD`, as in git).
 * Anything else is refused: a single revision is ambiguous here (git reads
 * `git diff A` as "A against the working tree", `git log A` as "everything
 * reachable from A"), and neither is a commit range.
 */
export function parseRangeSpec(spec: string): ParsedRange {
  const three = spec.indexOf('...');
  const two = spec.indexOf('..');
  if (two < 0) {
    throw usageError`--range expects <base>..<head> or <base>...<head>, got '${spec}'.
Example: --range origin/main..HEAD`;
  }
  const mergeBase = three === two;
  const base = spec.slice(0, two);
  const head = spec.slice(two + (mergeBase ? 3 : 2)) || 'HEAD';
  for (const [side, rev] of [['base', base], ['head', head]] as const) {
    if (rev.length === 0 || rev.startsWith('-') || rev.includes('..') || /[\s\0]/.test(rev)) {
      throw usageError`--range has no usable ${side} revision in '${spec}'.
Example: --range origin/main..HEAD`;
    }
  }
  return { base, head, mergeBase };
}

function git(cwd: string, args: string[], env?: NodeJS.ProcessEnv): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 256 * 1024 * 1024,
    env: env ?? process.env,
  });
}

function tryGit(cwd: string, args: string[]): string | null {
  try {
    return git(cwd, args).trim();
  } catch {
    return null;
  }
}

function commitOf(repoRoot: string, rev: string, spec: string): string {
  const sha = tryGit(repoRoot, ['rev-parse', '--verify', '--quiet', `${rev}^{commit}`]);
  if (!sha) {
    throw usageError`--range ${spec}: '${rev}' is not a commit in this repository.
In a shallow CI checkout, fetch the base first (for example: git fetch origin main).`;
  }
  return sha;
}

/**
 * Resolve the request against the repository that contains `targetDir`.
 * Every failure is a refusal (`UsageError`) naming what to do; git's own
 * stderr is not relayed.
 */
export function resolveChangeScope(targetDir: string, req: ChangeScopeRequest): ChangeScope {
  const flag = req.kind === 'range' ? '--range' : '--staged';
  const repoRoot = tryGit(targetDir, ['rev-parse', '--show-toplevel']);
  if (!repoRoot) {
    throw usageError`${flag} scans a change recorded in git, and ${targetDir} is not inside a git work tree.
Run it from a clone of the repository, or drop ${flag} to scan the directory as it is.`;
  }
  const prefix = tryGit(targetDir, ['rev-parse', '--show-prefix']) ?? '';

  let baseTree: string;
  let headTree: string | null;
  let baseCommit: string | null;
  let headCommit: string | null;
  let diffArgs: string[];
  if (req.kind === 'range') {
    const parsed = parseRangeSpec(req.spec);
    headCommit = commitOf(repoRoot, parsed.head, req.spec);
    const baseTip = commitOf(repoRoot, parsed.base, req.spec);
    if (parsed.mergeBase) {
      const mb = tryGit(repoRoot, ['merge-base', baseTip, headCommit]);
      if (!mb) {
        throw usageError`--range ${req.spec}: '${parsed.base}' and '${parsed.head}' have no common ancestor, so there is no merge base to measure from.
Use the two-dot form (--range ${parsed.base}..${parsed.head}) to compare the two trees directly.`;
      }
      baseCommit = mb;
    } else {
      baseCommit = baseTip;
    }
    baseTree = baseCommit;
    headTree = headCommit;
    diffArgs = ['diff', '--name-status', '-z', '--find-renames', '--no-ext-diff', baseCommit, headCommit];
  } else {
    headCommit = null;
    headTree = null;
    baseCommit = tryGit(repoRoot, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']) || null;
    // An unborn branch: everything staged is new. The empty tree's id depends
    // on the repository's hash algorithm, so ask git for it.
    baseTree = baseCommit
      ?? execFileSync('git', ['-C', repoRoot, 'hash-object', '-t', 'tree', '--stdin'], { input: '', encoding: 'utf8' }).trim();
    diffArgs = ['diff', '--cached', '--name-status', '-z', '--find-renames', '--no-ext-diff', baseTree];
  }

  const renames = new Map<string, string>();
  const fields = git(repoRoot, diffArgs).split('\0');
  for (let i = 0; i < fields.length; ) {
    const status = fields[i];
    if (!status) break;
    if (status.startsWith('R') || status.startsWith('C')) {
      if (status.startsWith('R')) renames.set(fields[i + 1], fields[i + 2]);
      i += 3;
    } else {
      i += 2;
    }
  }

  return {
    mode: req.kind,
    range: req.kind === 'range' ? req.spec : null,
    baseCommit,
    headCommit,
    repoRoot,
    prefix: prefix.replace(/\\/g, '/'),
    renames,
    baseTree,
    headTree,
  };
}

export interface MaterializedTrees {
  /** The scan target inside the head tree. */
  headDir: string;
  /** The scan target inside the base tree. */
  baseDir: string;
  cleanup: () => void;
}

/**
 * Write both sides into a private temp directory through a throwaway index
 * (`GIT_INDEX_FILE`), so neither the working tree nor `.git/index` is
 * touched. `--staged` reads a COPY of the real index. The last path component
 * of each root is the repository's name, so a report that shows the target's
 * basename shows the user's, not a temp name.
 */
export function materializeTrees(scope: ChangeScope): MaterializedTrees {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-change-'));
  const cleanup = () => {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  try {
    const name = path.basename(scope.repoRoot) || 'repo';
    const write = (side: 'base' | 'head', treeish: string | null): string => {
      const root = path.join(tmp, side, name);
      fs.mkdirSync(root, { recursive: true });
      const indexFile = path.join(tmp, `${side}.index`);
      if (treeish === null) {
        const realIndex = path.resolve(scope.repoRoot, git(scope.repoRoot, ['rev-parse', '--git-path', 'index']).trim());
        if (fs.existsSync(realIndex)) fs.copyFileSync(realIndex, indexFile);
      }
      const env = { ...process.env, GIT_INDEX_FILE: indexFile };
      if (treeish !== null) git(scope.repoRoot, ['read-tree', treeish], env);
      if (fs.existsSync(indexFile)) {
        git(scope.repoRoot, ['checkout-index', '--all', '--force', `--prefix=${root}${path.sep}`], env);
      }
      const dir = path.join(root, ...scope.prefix.split('/').filter(Boolean));
      fs.mkdirSync(dir, { recursive: true });
      return dir;
    };
    return { baseDir: write('base', scope.baseTree), headDir: write('head', scope.headTree), cleanup };
  } catch (err) {
    cleanup();
    throw err;
  }
}

/** The fields of a finding the classification reads. */
export interface ScopedFinding {
  checkId: string;
  file?: string;
  line?: number;
  message?: string;
  passed?: boolean;
  notApplicable?: unknown;
}

function relFile(file: string, root: string): string {
  const abs = path.isAbsolute(file) ? file : path.join(root, file);
  return path.relative(root, abs).split(path.sep).join('/');
}

/**
 * Split head findings into those the change introduced and those already
 * present at the base. Only failing records are classified; passed and
 * not-applicable records are returned untouched in `kept` (they set no exit
 * code and score nothing).
 */
export function classifyAgainstBase<T extends ScopedFinding>(
  headFindings: readonly T[],
  baseFindings: readonly ScopedFinding[],
  scope: Pick<ChangeScope, 'prefix' | 'renames'>,
  dirs: { headDir: string; baseDir: string },
): { kept: T[]; introduced: number; preExisting: number } {
  const lineCache = new Map<string, string[] | null>();
  const lineAt = (root: string, rel: string, line: number): string | undefined => {
    const key = root + '\0' + rel;
    if (!lineCache.has(key)) {
      try {
        lineCache.set(key, fs.readFileSync(path.join(root, rel), 'utf8').split(/\r?\n/));
      } catch {
        lineCache.set(key, null);
      }
    }
    const lines = lineCache.get(key);
    return lines && line >= 1 && line <= lines.length ? lines[line - 1] : undefined;
  };
  const roots = [dirs.headDir, dirs.baseDir];
  const normalizeMessage = (m: string | undefined): string => {
    let out = m ?? '';
    // A message that embeds the scan root names a different temp directory
    // on each side; the identity must not depend on it.
    for (const r of roots) out = out.split(r).join('<root>');
    return out;
  };
  // Renames are recorded repository-relative; findings are relative to the
  // scan target, which is `prefix` inside the repository.
  const renameInScope = new Map<string, string>();
  for (const [from, to] of scope.renames) {
    if (from.startsWith(scope.prefix) && to.startsWith(scope.prefix)) {
      renameInScope.set(from.slice(scope.prefix.length), to.slice(scope.prefix.length));
    }
  }
  const identity = (f: ScopedFinding, root: string, side: 'base' | 'head'): string => {
    const rel = f.file ? relFile(f.file, root) : '';
    const file = side === 'base' ? (renameInScope.get(rel) ?? rel) : rel;
    const content = f.file && typeof f.line === 'number' ? lineAt(root, rel, f.line) : undefined;
    const subject = content !== undefined ? `L\0${content.trim()}` : `M\0${normalizeMessage(f.message)}`;
    return `${f.checkId}\0${file}\0${subject}`;
  };
  const classified = (f: ScopedFinding) => f.passed === false && !f.notApplicable;

  const available = new Map<string, number>();
  for (const f of baseFindings) {
    if (!classified(f)) continue;
    const k = identity(f, dirs.baseDir, 'base');
    available.set(k, (available.get(k) ?? 0) + 1);
  }

  const kept: T[] = [];
  let introduced = 0;
  let preExisting = 0;
  for (const f of headFindings) {
    if (!classified(f)) {
      kept.push(f);
      continue;
    }
    const k = identity(f, dirs.headDir, 'head');
    const n = available.get(k) ?? 0;
    if (n > 0) {
      available.set(k, n - 1);
      preExisting += 1;
    } else {
      kept.push(f);
      introduced += 1;
    }
  }
  return { kept, introduced, preExisting };
}
