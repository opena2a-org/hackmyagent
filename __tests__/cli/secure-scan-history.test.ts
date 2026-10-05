/**
 * #536 — `secure --scan-history` through the built binary.
 *
 * The issue's reproduction: commit a key, delete the file, commit the deletion.
 * Without the flag `secure` reads only the tree, where the file no longer
 * exists, and the run scored 98/100 at exit 0. With it, the key is reported at
 * the commit that added it and the run fails.
 *
 * The token-shaped value is assembled at runtime: the repository's token-shape
 * guard rejects any committed line that matches a provider shape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

beforeAll(assertDistFreshIfPresent);

const QUICK = ['--scan-depth', 'quick', '--no-machine-posture'];
// Real-shaped: no fixture marker and no placeholder word, so the history pass
// reports it as the tree scan would.
const KEY = 'sk-' + 'proj-' + 'q8Rv2Lm7Nc4Wb9Hk1Zp6Jt3Yd5Gf0Ms4Hb7Kw2Pn';
const FAKE_KEY = 'sk-' + 'proj-' + 'FAKE1234567890abcdef'.repeat(2) + 'FAKE12';
const AWS = 'AKIA' + 'Q3ZR7M2KV9JLW4NB';

const git = (dir: string, ...args: string[]) =>
  execFileSync('git', ['-C', dir, ...args], { env: gitFreeEnv(), encoding: 'utf8' }).trim();

let repo: string;
let plain: string;
let addCommit: string;
/** History adds keys to a test file only; the file stays in the tree. */
let testOnly: string;
/** The same test file, then a real-shaped key added and deleted in src/config.ts. */
let mixed: string;
let configCommit: string;

beforeAll(() => {
  repo = fs.realpathSync(tempDir('hma-536-'));
  plain = fs.realpathSync(tempDir('hma-536-plain-'));
  initThrowawayRepo(repo);
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'init');
  fs.writeFileSync(path.join(repo, 'leaked.py'), `KEY = "${KEY}"\n`);
  git(repo, 'add', 'leaked.py');
  git(repo, 'commit', '-q', '-m', 'add config');
  addCommit = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'rm', '-q', 'leaked.py');
  git(repo, 'commit', '-q', '-m', 'remove config');

  testOnly = fs.realpathSync(tempDir('hma-536-test-'));
  mixed = fs.realpathSync(tempDir('hma-536-mixed-'));
  for (const dir of [testOnly, mixed]) {
    initThrowawayRepo(dir);
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'src', 'auth.test.ts'), `const fake = "${FAKE_KEY}";\nconst shaped = "${AWS}";\n`);
    git(dir, 'add', 'src/auth.test.ts');
    git(dir, 'commit', '-q', '-m', 'add test');
  }
  fs.writeFileSync(path.join(mixed, 'src', 'config.ts'), `export const key = "${KEY}";\n`);
  git(mixed, 'add', 'src/config.ts');
  git(mixed, 'commit', '-q', '-m', 'add config');
  configCommit = git(mixed, 'rev-parse', 'HEAD');
  git(mixed, 'rm', '-q', 'src/config.ts');
  git(mixed, 'commit', '-q', '-m', 'remove config');
});

function run(dir: string, args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, ...args, ...QUICK], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...gitFreeEnv(), NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('secure --scan-history (#536)', { timeout: 300_000 }, () => {
  it('control: without the flag the deleted key is not reported and the run passes', () => {
    const r = run(repo, ['--json']);
    const doc = JSON.parse(r.stdout);
    expect(doc.findings.some((f: { checkId: string }) => f.checkId === 'CRED-HIST-001')).toBe(false);
    expect(doc.history).toBeUndefined();
    expect(r.status).toBe(0);
  });

  it('--json reports the key at the commit that added it and exits 1', () => {
    const r = run(repo, ['--scan-history', '--json']);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout);
    const hits = doc.findings.filter((f: { checkId: string }) => f.checkId === 'CRED-HIST-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: 'critical', file: 'leaked.py', line: 1, commit: addCommit });
    expect(doc.history).toEqual({ commitsScanned: 3, credentialsFound: 1 });
    expect(doc.exitCode).toBe(1);
    expect(r.stdout).not.toContain(KEY);
  });

  it('the text report cites commit:file:line, a Verify that reads the commit, and the commits read', () => {
    const r = run(repo, ['--scan-history']);
    const short = addCommit.slice(0, 12);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('3 commits of history read');
    expect(r.stdout).toContain(`${short}:leaked.py:1`);
    expect(r.stdout).toContain(`Verify: git -C ${repo} show ${short}:./leaked.py | sed -n '1p'`);
    expect(r.stdout).toContain(`Fix: Rotate this OPENAI_API_KEY at its issuer`);
    expect(r.stdout).not.toContain(KEY);
  });

  it('sarif carries the commit beside the path', () => {
    const r = run(repo, ['--scan-history', '--format', 'sarif']);
    const sarif = JSON.parse(r.stdout);
    const result = sarif.runs[0].results.find((x: { ruleId: string }) => x.ruleId === 'CRED-HIST-001');
    expect(result.properties).toEqual({ commit: addCommit });
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('leaked.py');
  });

  it('--since bounds the read: after the commit that added the key, nothing is found', () => {
    const r = run(repo, ['--scan-history', '--since', 'HEAD~1', '--json']);
    const doc = JSON.parse(r.stdout);
    expect(doc.history).toEqual({ commitsScanned: 1, since: 'HEAD~1', credentialsFound: 0 });
    expect(r.status).toBe(0);
  });

  it('a key added to a *.test.ts gives no critical, the same as the tree scan', () => {
    type F = { checkId: string; severity: string; passed: boolean; file?: string };
    const critical = (stdout: string) =>
      (JSON.parse(stdout).findings as F[])
        .filter((f) => !f.passed && f.severity === 'critical')
        .map((f) => `${f.checkId} ${f.file ?? ''}`)
        .sort();
    const tree = run(testOnly, ['--json']);
    const history = run(testOnly, ['--scan-history', '--json']);
    expect(critical(history.stdout)).toEqual([]);
    expect(critical(history.stdout)).toEqual(critical(tree.stdout));
    expect(JSON.parse(history.stdout).history).toEqual({ commitsScanned: 1, credentialsFound: 0 });
    expect(history.status).toBe(tree.status);
  });

  it('a real-shaped key added and then deleted in src/config.ts stays critical', () => {
    const r = run(mixed, ['--scan-history', '--json']);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout);
    const hits = doc.findings.filter((f: { checkId: string }) => f.checkId === 'CRED-HIST-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: 'critical', file: 'src/config.ts', line: 1, commit: configCommit });
    expect(doc.history).toEqual({ commitsScanned: 3, credentialsFound: 1 });
  });

  it.each([
    ['--since without --scan-history', () => run(repo, ['--since', 'HEAD~1']), '--since sets where --scan-history starts reading'],
    ['a directory that is not a git work tree', () => run(plain, ['--scan-history']), 'is not inside a git work tree'],
    ['an unknown --since ref', () => run(repo, ['--scan-history', '--since', 'no-such-ref']), '--since no-such-ref is not a ref or commit'],
    ['a --since that is an option', () => run(repo, ['--scan-history', '--since=--all']), 'is not a ref or commit'],
    ['-b', () => run(repo, ['--scan-history', '-b', 'oasb-1']), '--scan-history is not available with -b oasb-1'],
  ])('refuses %s before scanning', (_label, invoke, message) => {
    const r = invoke();
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(message);
    expect(r.stdout).toBe('');
  });
});
