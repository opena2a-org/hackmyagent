/**
 * #537 — `secure --range <base>..<head>` and `secure --staged` report only
 * what a change introduces.
 *
 * Before: `secure` had no change-scoped mode, so as a pull request gate it
 * failed every pull request in a repository with one pre-existing finding.
 * The pair of cells that matters is the first two: a range that touches an
 * unrelated file over a base that already holds a secret must exit 0, and a
 * range that adds a secret must exit 1 citing the added line. A scanner that
 * ignored the range would pass the second cell and fail the first.
 *
 * Every cell fails on a build without the flags (Commander refuses the
 * unknown option); the tree-scan cell is a pin that holds on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { gitFreeEnv } from '../helpers/throwaway-repo';

beforeAll(assertDistFreshIfPresent);

// Built at runtime so this source file carries no credential-shaped literal.
const OPENAI = 'sk-proj-' + 'FAKE' + 'abcdefghijklmnopqrstuvwxyz0123456789ABCD';
const ANTHROPIC = 'sk-ant-api03-' + 'FAKE' + 'zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUTSRQPONMLK';

const QUICK = ['--scan-depth', 'quick', '--no-machine-posture', '--registry-url', 'http://localhost:9'];

let root: string;
let repo: string;
let home: string;
const sha: Record<string, string> = {};

function git(args: string[], cwd = repo): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    // gitFreeEnv: under a git hook GIT_DIR points at THIS repository (#348).
    env: { ...gitFreeEnv(), GIT_CONFIG_NOSYSTEM: '1', HOME: home },
  }).trim();
}

function write(rel: string, text: string): void {
  fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true });
  fs.writeFileSync(path.join(repo, rel), text);
}

function commit(name: string, paths: string[]): void {
  git(['add', '--', ...paths]);
  git(['commit', '-q', '-m', name]);
  sha[name] = git(['rev-parse', 'HEAD']);
}

const config = (keys: string[]) =>
  '{\n  "server": { "port": 3000 },\n  "api": {\n'
  + keys.map((k, i) => `    "key${i}": "${k}"`).join(',\n')
  + '\n  }\n}\n';

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-537-'));
  home = path.join(root, 'home');
  repo = path.join(root, 'repo');
  fs.mkdirSync(home);
  fs.mkdirSync(repo);
  git(['init', '-q', '-b', 'main', '.']);
  git(['config', 'user.email', 'fixture@example.invalid']);
  git(['config', 'user.name', 'fixture']);
  git(['config', 'commit.gpgsign', 'false']);

  write('package.json', '{ "name": "fx537", "version": "1.0.0", "private": true }\n');
  write('index.js', 'module.exports = () => 1;\n');
  // Two lines above the key, so the "unrelated" commit below can move it.
  write('config.json', '{\n  "api": {\n' + `    "key0": "${OPENAI}"\n  }\n}\n`);
  commit('base', ['package.json', 'index.js', 'config.json']);

  // Touches an unrelated file, and shifts the pre-existing key down a line.
  write('index.js', 'module.exports = () => 2;\n');
  write('config.json', config([OPENAI]));
  commit('unrelated', ['index.js', 'config.json']);

  write('config.json', config([OPENAI, ANTHROPIC]));
  commit('adds', ['config.json']);

  git(['mv', 'config.json', 'settings.json']);
  git(['commit', '-q', '-m', 'rename']);
  sha.rename = git(['rev-parse', 'HEAD']);

  git(['rm', '-q', 'settings.json']);
  git(['commit', '-q', '-m', 'delete']);
  sha.delete = git(['rev-parse', 'HEAD']);
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', repo, ...args, ...QUICK], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function runJson(args: string[]) {
  const r = run([...args, '--json']);
  let doc: any;
  try { doc = JSON.parse(r.stdout); } catch { doc = undefined; }
  return { ...r, doc };
}

const failing = (doc: any) => (doc?.findings ?? []).filter((f: any) => f.passed === false);
const cred = (doc: any) => failing(doc).filter((f: any) => f.checkId === 'CRED-001');

describe('#537 secure --range / --staged report only what the change introduces', { timeout: 600_000 }, () => {
  it('pin: a tree scan of the same head still reports the pre-existing secret', () => {
    git(['checkout', '-q', '--detach', sha.unrelated]);
    try {
      const r = runJson([]);
      expect(r.status, r.stderr).toBe(1);
      expect(cred(r.doc)).toHaveLength(1);
      expect(r.doc.changeScope).toBeUndefined();
    } finally {
      git(['checkout', '-q', 'main']);
    }
  });

  it('a base that already holds a secret and a change to an unrelated file exits 0', () => {
    const r = runJson(['--range', `${sha.base}..${sha.unrelated}`]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.doc.exitCode).toBe(0);
    expect(cred(r.doc)).toEqual([]);
    expect(r.doc.changeScope).toMatchObject({
      mode: 'range',
      range: `${sha.base}..${sha.unrelated}`,
      baseCommit: sha.base,
      headCommit: sha.unrelated,
      introduced: 0,
    });
    expect(r.doc.changeScope.preExisting).toBeGreaterThanOrEqual(1);
  });

  it('a change that adds a secret exits 1 and cites the added line', () => {
    const r = runJson(['--range', `${sha.base}..${sha.adds}`]);
    expect(r.status, r.stderr).toBe(1);
    const found = cred(r.doc);
    expect(found).toHaveLength(1);
    expect(found[0].file).toBe('config.json');
    // The added key is the second entry: line 5 of the 7-line config.
    const lines = config([OPENAI, ANTHROPIC]).split('\n');
    expect(lines[found[0].line - 1]).toContain('key1');
    expect(r.doc.changeScope.introduced).toBeGreaterThanOrEqual(1);
  });

  it('the three-dot form measures from the merge base', () => {
    const r = runJson(['--range', `${sha.unrelated}...${sha.adds}`]);
    expect(r.status, r.stderr).toBe(1);
    expect(r.doc.changeScope.baseCommit).toBe(sha.unrelated);
    expect(cred(r.doc)).toHaveLength(1);
  });

  it('a rename that moves a pre-existing secret introduces nothing', () => {
    const r = runJson(['--range', `${sha.adds}..${sha.rename}`]);
    expect(r.status, r.stderr).toBe(0);
    expect(cred(r.doc)).toEqual([]);
  });

  it('a file the change deletes reports nothing', () => {
    const r = runJson(['--range', `${sha.adds}..${sha.delete}`]);
    expect(r.status, r.stderr).toBe(0);
    expect(failing(r.doc).filter((f: any) => f.file === 'config.json' || f.file === 'settings.json')).toEqual([]);
  });

  it('the text report says how many findings were left out', () => {
    const r = run(['--range', `${sha.base}..${sha.unrelated}`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Changes in [0-9a-f]+\.\.[0-9a-f]+: 0 findings introduced\. \d+ findings? already present at [0-9a-f]{12} (is|are) not reported/);
  });

  it('--staged reports what is staged and nothing that is only in the working tree', () => {
    git(['checkout', '-q', sha.adds, '--', 'config.json']);
    git(['reset', '-q', '--', 'config.json']);
    const unstaged = runJson(['--staged']);
    expect(unstaged.status, unstaged.stderr).toBe(0);
    expect(unstaged.doc.changeScope).toMatchObject({ mode: 'staged', headCommit: null, introduced: 0 });

    git(['add', '--', 'config.json']);
    const staged = runJson(['--staged']);
    expect(staged.status, staged.stderr).toBe(1);
    expect(cred(staged.doc)).toHaveLength(1);
    // The repository's own index is read, not rewritten.
    expect(git(['status', '--porcelain'])).toBe('A  config.json');
    git(['rm', '-q', '--cached', '--', 'config.json']);
    fs.rmSync(path.join(repo, 'config.json'));
  });

  it('refuses a target outside git, an unknown revision, a malformed range, and flags that write or publish', () => {
    const outside = spawnSync(process.execPath, [CLI, 'secure', home, '--range', 'a..b', ...QUICK], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, GIT_CEILING_DIRECTORIES: root },
      timeout: 240_000,
    });
    expect(outside.status).toBe(1);
    expect(outside.stderr).toMatch(/is not inside a git work tree/);

    const unknown = run(['--range', 'no-such-branch..HEAD']);
    expect(unknown.status).toBe(1);
    expect(unknown.stderr).toMatch(/'no-such-branch' is not a commit in this repository/);

    const single = run(['--range', 'HEAD']);
    expect(single.status).toBe(1);
    expect(single.stderr).toMatch(/--range expects <base>\.\.<head>/);

    const conflict = run(['--range', `${sha.base}..${sha.adds}`, '--fix', '--publish']);
    expect(conflict.status).toBe(1);
    expect(conflict.stderr).toMatch(/cannot be combined with --fix, --publish/);
  });
});
