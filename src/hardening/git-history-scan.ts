/**
 * Credential detection over a repository's git history (#536).
 *
 * Every other `secure` pass reads the checked-out tree, so a credential that was
 * committed and later deleted was invisible to all of them: the scan reported
 * clean on exactly the repository state that still serves the value to every
 * clone. This pass reads the lines each commit ADDED, from `git log -p`, and
 * reports each distinct credential value once, at the commit that introduced it.
 *
 * A history hit gets the treatment a tree hit gets for the same path and value:
 * a line added to a test file (`isTestPath`) is not reported, as the tree scan
 * does not report it, and a value carrying a fixture marker or a placeholder
 * word is not a credential here either (`isFixtureOrPlaceholderValue`).
 *
 * Git is run as a child process with an argument vector (never a shell), with
 * every option that lets repository config run a program or reshape the output
 * pinned on the command line: the target is the scanned tree, and its
 * `.git/config` is as much scanned input as its files are.
 */

import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { isTestPath } from './path-context';

/** One credential pattern, in the shape `CREDENTIAL_PATTERNS` already uses. */
export interface HistoryCredentialPattern {
  name: string;
  pattern: RegExp;
}

/** A credential value found in a line some commit added. */
export interface HistoryCredentialHit {
  /** Full object name of the commit that first added the value. */
  commit: string;
  /** Path at that commit, relative to the scanned directory. */
  file: string;
  /** 1-based line of the value in `file` at `commit`. */
  line: number;
  /** Pattern name, e.g. `OPENAI_API_KEY`. Never the value. */
  credentialType: string;
}

export interface HistoryScanSummary {
  /** Distinct commits whose changes were read. */
  commitsScanned: number;
  /** The `--since` boundary as given, when one was. */
  since?: string;
  hits: HistoryCredentialHit[];
}

/**
 * Resolved inputs for a history scan. Produced by `resolveHistoryScan` before
 * any scanning starts, so every way the request can be refused is refused up
 * front instead of half way through a report.
 */
export interface HistoryScanPlan {
  /** The directory git runs in: the scan target. */
  cwd: string;
  /** Commit the `--since` ref resolved to, when one was given. */
  sinceCommit?: string;
  /** The `--since` ref as the user typed it. */
  since?: string;
}

/**
 * Options pinned on every git invocation. Each one closes a way the scanned
 * repository's own config could run a program or change the output this
 * module parses:
 *
 *  - `log.showSignature=false`: signature display runs `gpg.program`, which
 *    the repository's config names;
 *  - `core.fsmonitor=false`: the hook program is repository config too;
 *  - `core.quotePath=true`: the one path spelling `unquoteGitPath` decodes.
 */
const GIT_CONFIG_PINS = [
  '-c', 'log.showSignature=false',
  '-c', 'core.fsmonitor=false',
  '-c', 'core.quotePath=true',
];

/**
 * The environment git runs in: the caller's, minus every `GIT_*` variable.
 *
 * An inherited `GIT_DIR` (git exports one to every hook it runs, so a scan
 * from a pre-push hook has one) points git at a repository other than the
 * target, and the scan would then report another repository's history under
 * this one's name.
 */
export function gitEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('GIT_')) env[k] = v;
  }
  return env;
}

function runGit(
  cwd: string,
  args: string[],
): Promise<{ code: number; stdout: string; stderr: string; missing: boolean }> {
  return new Promise((resolve) => {
    execFile(
      'git',
      ['--no-pager', ...GIT_CONFIG_PINS, ...args],
      { cwd, env: gitEnvironment(), maxBuffer: 1024 * 1024, encoding: 'utf8' },
      (err, stdout, stderr) => {
        const raw = (err as { code?: unknown } | null)?.code;
        resolve({
          code: err ? (typeof raw === 'number' ? raw : -1) : 0,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          missing: raw === 'ENOENT',
        });
      },
    );
  });
}

/**
 * A history scan that cannot start. `subject` says which input the reason is
 * about, so the caller can name it: the scan target, the `--since` ref, or git
 * itself. `detail` is git's own first stderr line, when it gave one; it is
 * external text and the caller escapes it like any other.
 */
export class HistoryScanRefusal extends Error {
  constructor(
    readonly subject: 'target' | 'since' | 'git',
    message: string,
    readonly detail?: string,
  ) {
    super(message);
    this.name = 'HistoryScanRefusal';
  }
}

function firstLine(text: string): string | undefined {
  const line = text.split('\n').map((l) => l.trim()).find((l) => l.length > 0);
  return line;
}

/**
 * Check that `dir` is inside a git work tree and that `since`, when given,
 * names a commit. Throws `HistoryScanRefusal` otherwise.
 */
export async function resolveHistoryScan(dir: string, since?: string): Promise<HistoryScanPlan> {
  const inside = await runGit(dir, ['rev-parse', '--is-inside-work-tree']);
  if (inside.missing) {
    throw new HistoryScanRefusal('git', 'needs git on PATH, and git was not found');
  }
  if (inside.code !== 0 || inside.stdout.trim() !== 'true') {
    throw new HistoryScanRefusal('target', 'is not inside a git work tree, so it has no history to scan', firstLine(inside.stderr));
  }
  if (since === undefined) return { cwd: dir };
  // A ref that starts with `-` would be read as an option by every git
  // command it reaches. No ref name can start with one.
  if (since.length === 0 || since.startsWith('-')) {
    throw new HistoryScanRefusal('since', 'is not a ref or commit in this repository');
  }
  const resolved = await runGit(dir, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${since}^{commit}`]);
  const sha = resolved.stdout.trim();
  if (resolved.code !== 0 || !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(sha)) {
    throw new HistoryScanRefusal('since', 'is not a ref or commit in this repository');
  }
  return { cwd: dir, since, sinceCommit: sha };
}

/**
 * Decode a path as `core.quotePath=true` prints it: wrapped in double quotes
 * with C-style escapes when it holds a quote, a backslash, a control byte or
 * a non-ASCII byte. Octal escapes are bytes, so they are collected and decoded
 * as UTF-8 together.
 */
export function unquoteGitPath(raw: string): string {
  if (!(raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"'))) return raw;
  const body = raw.slice(1, -1);
  const bytes: number[] = [];
  const simple: Record<string, number> = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, '\\': 92 };
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== '\\') {
      for (const b of Buffer.from(ch, 'utf8')) bytes.push(b);
      continue;
    }
    const next = body[i + 1];
    if (next !== undefined && /[0-7]/.test(next)) {
      const oct = body.slice(i + 1, i + 4);
      if (/^[0-7]{3}$/.test(oct)) {
        bytes.push(parseInt(oct, 8));
        i += 3;
        continue;
      }
    }
    if (next !== undefined && simple[next] !== undefined) {
      bytes.push(simple[next]);
      i += 1;
      continue;
    }
    bytes.push(92);
  }
  return Buffer.from(bytes).toString('utf8');
}

/**
 * Fixture markers: the credential analyzer reads a value carrying one of these
 * as a test fixture, in every context. `EXAMPLE` is the suffix of the access
 * key id in the AWS documentation. Kept equal to the analyzer's list.
 */
const FIXTURE_MARKER = /FAKE|EXAMPLE|PLACEHOLDER|TEST|DUMMY|SAMPLE|XXX|YOUR_|<YOUR/i;

/**
 * Placeholder words: the words the env-value check skips a value for, standing
 * alone in it (a key whose body reads `changeme-...`). Kept equal to that
 * check's list.
 */
const PLACEHOLDER_WORD =
  /(?:^|[-_])your[-_]|\b(?:changeme|change_me|placeholder|example|dummy|replace[-_ ]?me|todo|tbd|none|null|undefined)\b/i;

/**
 * True when the tree scan would not report `value` as a credential: it carries
 * a fixture marker or a placeholder word.
 */
export function isFixtureOrPlaceholderValue(value: string): boolean {
  return FIXTURE_MARKER.test(value) || PLACEHOLDER_WORD.test(value);
}

/**
 * Every value in `line` that one of `patterns` matches, outside a well-formed
 * environment-variable reference when `outsideRef` says so.
 */
function credentialMatches(
  line: string,
  patterns: readonly HistoryCredentialPattern[],
  outsideRef: (text: string, pattern: RegExp) => boolean,
): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  for (const { name, pattern } of patterns) {
    if (!outsideRef(line, pattern)) continue;
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      out.push({ name, value: m[0] });
    }
  }
  return out;
}

/**
 * Parser state over `git log -p --unified=0` output. Fed one line at a time
 * (split on `\n` only: a lone `\r` inside an added line is content, and
 * splitting on it would desynchronise the hunk counts).
 *
 * A commit header is the NUL byte the `--format` string emits. Inside a hunk
 * every line starts with `+`, `-`, ` ` or `\`, and the hunk's own counts say
 * where it ends, so no added line can be mistaken for a header however it is
 * spelled.
 */
export class HistoryDiffParser {
  private commit: string | undefined;
  private file: string | undefined;
  private newLine = 0;
  private oldLeft = 0;
  private newLeft = 0;
  private readonly seenValues = new Set<string>();
  readonly commits = new Set<string>();
  readonly hits: HistoryCredentialHit[] = [];

  constructor(
    private readonly patterns: readonly HistoryCredentialPattern[],
    private readonly outsideRef: (text: string, pattern: RegExp) => boolean,
  ) {}

  feed(line: string): void {
    if (this.oldLeft > 0 || this.newLeft > 0) {
      this.hunkLine(line);
      return;
    }
    if (line.startsWith('\u0000')) {
      const sha = line.slice(1).trim();
      this.commit = /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(sha) ? sha : undefined;
      if (this.commit) this.commits.add(this.commit);
      this.file = undefined;
      return;
    }
    if (line.startsWith('diff --git ')) {
      this.file = undefined;
      return;
    }
    if (line.startsWith('+++ ')) {
      // Git ends the line with a TAB when the path holds a space. A path that
      // really ends in a TAB is printed quoted, so this TAB is never the path's.
      const target = line.slice(4).replace(/\t$/, '');
      if (target === '/dev/null') {
        this.file = undefined;
      } else {
        const unquoted = unquoteGitPath(target);
        this.file = unquoted.startsWith('b/') ? unquoted.slice(2) : unquoted;
      }
      return;
    }
    const hunk = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      this.oldLeft = hunk[1] === undefined ? 1 : Number(hunk[1]);
      this.newLine = Number(hunk[2]);
      this.newLeft = hunk[3] === undefined ? 1 : Number(hunk[3]);
    }
  }

  private hunkLine(line: string): void {
    const tag = line[0];
    if (tag === '+') {
      this.newLeft--;
      this.added(line.slice(1), this.newLine);
      this.newLine++;
    } else if (tag === '-') {
      this.oldLeft--;
    } else if (tag === ' ') {
      this.oldLeft--;
      this.newLeft--;
      this.newLine++;
    } else if (tag === '\\') {
      // "\ No newline at end of file": not a line of either side.
    } else {
      // Output that does not follow the hunk's own counts: stop trusting them
      // rather than read headers as content.
      this.oldLeft = 0;
      this.newLeft = 0;
      this.feed(line);
    }
  }

  private added(text: string, line: number): void {
    if (!this.commit || this.file === undefined) return;
    // A test file deliberately holds what it tests; the tree scan does not
    // report it, so neither does its history. Checked before the value digest
    // is recorded, so the same value added later outside a test file reports.
    if (isTestPath(this.file)) return;
    for (const { name, value } of credentialMatches(text, this.patterns, this.outsideRef)) {
      if (isFixtureOrPlaceholderValue(value)) continue;
      // Keyed by a digest, so the set never holds a credential.
      const key = createHash('sha256').update(name).update('\u0000').update(value).digest('hex');
      if (this.seenValues.has(key)) continue;
      this.seenValues.add(key);
      this.hits.push({ commit: this.commit, file: this.file, line, credentialType: name });
    }
  }
}

/**
 * Read every commit `plan` covers and return each distinct credential value at
 * the commit that introduced it.
 *
 * `--topo-order --reverse` puts every parent before its children, so the first
 * sighting of a value is its introduction. `-m` diffs a merge against each
 * parent, so content that exists only in a merge's resolution is read too; the
 * duplicates that brings are dropped by the value digest.
 *
 * Throws when git fails part way: a history the scan could not read to the end
 * must not report as a history with nothing in it.
 */
export async function scanGitHistory(
  plan: HistoryScanPlan,
  patterns: readonly HistoryCredentialPattern[],
  outsideRef: (text: string, pattern: RegExp) => boolean,
): Promise<HistoryScanSummary> {
  const parser = new HistoryDiffParser(patterns, outsideRef);
  const revs = plan.sinceCommit ? ['--all', `^${plan.sinceCommit}`] : ['--all'];
  const args = [
    '--no-pager', ...GIT_CONFIG_PINS,
    'log', ...revs,
    '--topo-order', '--reverse',
    '-p', '-m', '--root', '--unified=0',
    '--no-color', '--no-ext-diff', '--no-textconv', '--no-renames',
    '--src-prefix=a/', '--dst-prefix=b/',
    '--relative',
    '--format=%x00%H',
  ];

  await new Promise<void>((resolve, reject) => {
    const child = spawn('git', args, { cwd: plan.cwd, env: gitEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
    const decoder = new StringDecoder('utf8');
    let pending = '';
    let stderr = '';
    const take = (text: string) => {
      pending += text;
      let nl = pending.indexOf('\n');
      while (nl !== -1) {
        parser.feed(pending.slice(0, nl));
        pending = pending.slice(nl + 1);
        nl = pending.indexOf('\n');
      }
    };
    child.stdout.on('data', (chunk: Buffer) => take(decoder.write(chunk)));
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < 4096) stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) => {
      take(decoder.end());
      if (pending.length > 0) parser.feed(pending);
      if (code === 0) resolve();
      else reject(new Error(`git log exited with status ${code}${firstLine(stderr) ? `: ${firstLine(stderr)}` : ''}`));
    });
  });

  return {
    commitsScanned: parser.commits.size,
    ...(plan.since !== undefined ? { since: plan.since } : {}),
    hits: parser.hits,
  };
}

/** The 12-character abbreviation every rendered citation uses. */
export function shortCommit(commit: string): string {
  return commit.slice(0, 12);
}
