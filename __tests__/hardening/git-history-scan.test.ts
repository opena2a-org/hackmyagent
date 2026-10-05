/**
 * #536 — `secure --scan-history`: a credential committed and later deleted
 * from the tree is reported, at the commit that added it.
 *
 * Before this pass every scan read the checked-out tree only, so the issue's
 * reproduction (commit a key, delete the file, commit again) scored 98/100 at
 * exit 0 with nothing but GIT-001 — clean on exactly the repository state that
 * still serves the key to every clone.
 *
 * Token-shaped values are assembled at runtime: the repository's token-shape
 * guard rejects any committed line that matches a provider shape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync, chmodSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { HardeningScanner, CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef } from '../../src/hardening/scanner';
import {
  HistoryDiffParser,
  HistoryScanRefusal,
  resolveHistoryScan,
  scanGitHistory,
  unquoteGitPath,
  gitEnvironment,
  isFixtureOrPlaceholderValue,
} from '../../src/hardening/git-history-scan';
import { generateVerifyCommand } from '../../src/ui/verify-command';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

// Real-shaped: no fixture marker and no placeholder word, so the history pass
// reports them as the tree scan would.
const OPENAI = 'sk-' + 'proj-' + 'q8Rv2Lm7Nc4Wb9Hk1Zp6Jt3Yd5Gf0Ms4Hb7Kw2Pn';
const AWS = 'AKIA' + 'Q3ZR7M2KV9JLW4NB';
// Values the tree scan does not report: a fixture marker, the AWS
// documentation key, a placeholder word.
const FAKE_OPENAI = 'sk-' + 'proj-' + 'FAKE1234567890abcdef'.repeat(2) + 'FAKE12';
const AWS_DOC = 'AKIA' + 'IOSFODNN7EXAMPLE';
const ANTHROPIC_CHANGEME = 'sk-ant-' + 'api03-' + 'changeme-' + 'k4Pq9Wz2Lr7Tm1Vb6Nc3';

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', ['-C', dir, ...args], { env: gitFreeEnv(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}
function commitAll(dir: string, message: string, ...paths: string[]): string {
  if (paths.length > 0) git(dir, 'add', '--', ...paths);
  git(dir, 'commit', '-q', '--allow-empty', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}

function freshDir(): string {
  return realpathSync(tempDir('hma-hist-'));
}

/** The issue's reproduction: add a key, delete the file, commit the deletion. */
function removedSecretRepo(): { dir: string; addCommit: string; head: string } {
  const dir = freshDir();
  initThrowawayRepo(dir);
  git(dir, 'commit', '-q', '--allow-empty', '-m', 'init');
  writeFileSync(path.join(dir, 'leaked.py'), `KEY = "${OPENAI}"\n`);
  const addCommit = commitAll(dir, 'add config', 'leaked.py');
  git(dir, 'rm', '-q', 'leaked.py');
  const head = commitAll(dir, 'remove config');
  return { dir, addCommit, head };
}

describe('secure --scan-history reports a credential deleted from the tree (#536)', () => {
  let repo: ReturnType<typeof removedSecretRepo>;
  beforeAll(() => {
    repo = removedSecretRepo();
  });

  it('control: the tree scan alone does not see it (the defect the flag exists for)', async () => {
    const result = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick' });
    expect(result.findings.some((f) => f.checkId === 'CRED-HIST-001')).toBe(false);
    expect(result.history).toBeUndefined();
  });

  it('reports CRED-HIST-001 at commit:file:line, critical, counted against the score', async () => {
    const plan = await resolveHistoryScan(repo.dir);
    const withHistory = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan });
    const treeOnly = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick' });

    const hits = withHistory.findings.filter((f) => f.checkId === 'CRED-HIST-001');
    expect(hits).toHaveLength(1);
    const [hit] = hits;
    expect(hit.commit).toBe(repo.addCommit);
    expect(hit.file).toBe('leaked.py');
    expect(hit.line).toBe(1);
    expect(hit.severity).toBe('critical');
    expect(hit.passed).toBe(false);
    expect(hit.description).toContain(`${repo.addCommit.slice(0, 12)}:leaked.py:1`);
    expect(withHistory.history).toEqual({ commitsScanned: 3, credentialsFound: 1 });
    expect(withHistory.score).toBeLessThan(treeOnly.score);
  });

  it('the remedy is rotation, not the tree edit that cannot reach a commit', async () => {
    const plan = await resolveHistoryScan(repo.dir);
    const result = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan });
    const hit = result.findings.find((f) => f.checkId === 'CRED-HIST-001')!;
    expect(hit.fix).toMatch(/^Rotate /);
    expect(hit.fixable).toBe(false);
    expect(`${hit.fix} ${hit.guidance}`).not.toMatch(/protect|secretless|environment variable/i);
  });

  it('never carries the credential value in the result', async () => {
    const plan = await resolveHistoryScan(repo.dir);
    const result = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan });
    expect(JSON.stringify(result)).not.toContain(OPENAI);
  });

  it('an .hmaignore path rule and --ignore apply to a history finding like a tree finding', async () => {
    const plan = await resolveHistoryScan(repo.dir);
    const ignored = await new HardeningScanner().scan({
      targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan, ignore: ['CRED-HIST-001'],
    });
    expect(ignored.findings.some((f) => f.checkId === 'CRED-HIST-001')).toBe(false);
    expect(ignored.suppressed?.some((s) => s.checkId === 'CRED-HIST-001')).toBe(true);
  });

  it('the Verify command reads the line from the commit, and running it shows the flagged line', async () => {
    const plan = await resolveHistoryScan(repo.dir);
    const result = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan });
    const hit = result.findings.find((f) => f.checkId === 'CRED-HIST-001')!;
    const verify = generateVerifyCommand(hit, repo.dir);
    expect(verify).toBe(`git -C ${repo.dir} show ${repo.addCommit.slice(0, 12)}:./leaked.py | sed -n '1p'`);
    const shown = execFileSync('/bin/sh', ['-c', verify!], { env: gitFreeEnv(), encoding: 'utf8' });
    expect(shown).toContain('sk-' + 'proj-');
    // The tree-file form would verify nothing: the file is gone at HEAD.
    expect(existsSync(path.join(repo.dir, 'leaked.py'))).toBe(false);
  });
});

describe('a history hit gets the treatment a tree hit gets for the same path and value (#536)', () => {
  /**
   * The reproduction: a test file whose history adds keys (kept in the
   * tree), and a real-shaped key added and then deleted in `src/config.ts`.
   */
  function mixedRepo(): { dir: string; configCommit: string } {
    const dir = freshDir();
    initThrowawayRepo(dir);
    mkdirSync(path.join(dir, 'src'));
    writeFileSync(path.join(dir, 'src', 'auth.test.ts'), `const fake = "${FAKE_OPENAI}";\nconst shaped = "${AWS}";\n`);
    commitAll(dir, 'add test', 'src/auth.test.ts');
    writeFileSync(path.join(dir, 'src', 'config.ts'), `export const key = "${OPENAI}";\n`);
    const configCommit = commitAll(dir, 'add config', 'src/config.ts');
    git(dir, 'rm', '-q', 'src/config.ts');
    commitAll(dir, 'remove config');
    return { dir, configCommit };
  }

  it('a key added to a *.test.ts reports nothing, and one added then deleted in src/config.ts stays critical', async () => {
    const repo = mixedRepo();
    const plan = await resolveHistoryScan(repo.dir);
    const result = await new HardeningScanner().scan({ targetDir: repo.dir, scanDepth: 'quick', scanHistory: plan });
    const hits = result.findings.filter((f) => f.checkId === 'CRED-HIST-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'src/config.ts', line: 1, commit: repo.configCommit, severity: 'critical', passed: false,
    });
    expect(result.history).toEqual({ commitsScanned: 3, credentialsFound: 1 });
  });

  it('a repository whose history adds keys only to a test file fails no more checks than its tree scan', async () => {
    const dir = freshDir();
    initThrowawayRepo(dir);
    mkdirSync(path.join(dir, 'src'));
    writeFileSync(path.join(dir, 'src', 'auth.test.ts'), `const fake = "${FAKE_OPENAI}";\nconst shaped = "${AWS}";\n`);
    commitAll(dir, 'add test', 'src/auth.test.ts');
    const failing = (r: Awaited<ReturnType<HardeningScanner['scan']>>) =>
      r.findings.filter((f) => !f.passed).map((f) => `${f.checkId} ${f.severity} ${f.file ?? ''}`).sort();

    const tree = await new HardeningScanner().scan({ targetDir: dir, scanDepth: 'quick' });
    const withHistory = await new HardeningScanner().scan({
      targetDir: dir, scanDepth: 'quick', scanHistory: await resolveHistoryScan(dir),
    });
    expect(withHistory.findings.some((f) => f.checkId === 'CRED-HIST-001')).toBe(false);
    expect(withHistory.history).toEqual({ commitsScanned: 1, credentialsFound: 0 });
    expect(failing(withHistory)).toEqual(failing(tree));
  });

  const sha = 'b'.repeat(40);
  const parse = (lines: string[]) => {
    const p = new HistoryDiffParser(CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef);
    for (const line of [`\u0000${sha}`, ...lines]) p.feed(line);
    return p;
  };

  it.each([
    ['src/auth.test.ts'],
    ['src/auth.spec.js'],
    ['__tests__/helpers.ts'],
    ['pkg/client_test.go'],
    ['tests/client_test.py'],
  ])('a line added to the test file %s is not a hit', (file) => {
    expect(parse([`+++ b/${file}`, '@@ -0,0 +1 @@', `+k=${OPENAI}`]).hits).toEqual([]);
  });

  it('a value first added in a test file reports where it is later added outside one', () => {
    const p = parse([
      '+++ b/src/auth.test.ts', '@@ -0,0 +1 @@', `+k=${OPENAI}`,
      '+++ b/src/config.ts', '@@ -0,0 +1 @@', `+k=${OPENAI}`,
    ]);
    expect(p.hits).toEqual([{ commit: sha, file: 'src/config.ts', line: 1, credentialType: 'OPENAI_API_KEY' }]);
  });

  it.each([
    ['a fixture marker', FAKE_OPENAI],
    ['the AWS documentation key', AWS_DOC],
    ['a placeholder word', ANTHROPIC_CHANGEME],
  ])('a value carrying %s is not a hit', (_label, value) => {
    expect(isFixtureOrPlaceholderValue(value)).toBe(true);
    expect(parse(['+++ b/src/config.ts', '@@ -0,0 +1 @@', `+k=${value}`]).hits).toEqual([]);
  });

  it('a real-shaped value outside a test file is a hit', () => {
    expect(isFixtureOrPlaceholderValue(OPENAI)).toBe(false);
    expect(isFixtureOrPlaceholderValue(AWS)).toBe(false);
    const p = parse(['+++ b/src/config.ts', '@@ -0,0 +1,2 @@', `+a=${FAKE_OPENAI}`, `+b=${AWS}`]);
    expect(p.hits).toEqual([{ commit: sha, file: 'src/config.ts', line: 2, credentialType: 'AWS_ACCESS_KEY' }]);
  });
});

describe('history boundaries and attribution', () => {
  it('--since excludes commits reachable from the ref', async () => {
    const repo = removedSecretRepo();
    const after = await scanGitHistory(
      await resolveHistoryScan(repo.dir, 'HEAD~1'), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef,
    );
    expect(after.hits).toHaveLength(0);
    expect(after.commitsScanned).toBe(1);
    expect(after.since).toBe('HEAD~1');

    const fromInit = await scanGitHistory(
      await resolveHistoryScan(repo.dir, 'HEAD~2'), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef,
    );
    expect(fromInit.hits.map((h) => h.commit)).toEqual([repo.addCommit]);
  });

  it('reports a value once, at the commit that introduced it, however often later commits touch it', async () => {
    const dir = freshDir();
    initThrowawayRepo(dir);
    writeFileSync(path.join(dir, 'a.json'), `{"k":"${OPENAI}"}\n`);
    const first = commitAll(dir, 'one', 'a.json');
    writeFileSync(path.join(dir, 'a.json'), `{"x":1,\n"k":"${OPENAI}"}\n`);
    commitAll(dir, 'two', 'a.json');
    git(dir, 'mv', 'a.json', 'b.json');
    commitAll(dir, 'three');
    const summary = await scanGitHistory(await resolveHistoryScan(dir), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef);
    expect(summary.hits).toEqual([{ commit: first, file: 'a.json', line: 1, credentialType: 'OPENAI_API_KEY' }]);
  });

  it('reads branches that are not checked out, and content only a merge resolution added', async () => {
    const dir = freshDir();
    initThrowawayRepo(dir);
    writeFileSync(path.join(dir, 'base.txt'), 'base\n');
    commitAll(dir, 'base', 'base.txt');
    const main = git(dir, 'rev-parse', '--abbrev-ref', 'HEAD');
    git(dir, 'checkout', '-q', '-b', 'side');
    writeFileSync(path.join(dir, 'side.txt'), `aws=${AWS}\n`);
    const sideCommit = commitAll(dir, 'side', 'side.txt');
    git(dir, 'checkout', '-q', main);
    writeFileSync(path.join(dir, 'main.txt'), 'main\n');
    commitAll(dir, 'main', 'main.txt');
    git(dir, 'merge', '-q', '--no-ff', '--no-commit', 'side');
    writeFileSync(path.join(dir, 'base.txt'), `base\nkey=${OPENAI}\n`);
    const merge = commitAll(dir, 'merge', 'base.txt');
    git(dir, 'checkout', '-q', '-b', 'later');
    git(dir, 'checkout', '-q', main);

    const summary = await scanGitHistory(await resolveHistoryScan(dir), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef);
    const byType = Object.fromEntries(summary.hits.map((h) => [h.credentialType, h]));
    expect(byType.AWS_ACCESS_KEY).toMatchObject({ commit: sideCommit, file: 'side.txt', line: 1 });
    expect(byType.OPENAI_API_KEY).toMatchObject({ commit: merge, file: 'base.txt', line: 2 });
    expect(summary.hits).toHaveLength(2);
  });

  it('a target below the repository root reads only its own paths, relative to itself', async () => {
    const dir = freshDir();
    initThrowawayRepo(dir);
    mkdirSync(path.join(dir, 'pkg'));
    writeFileSync(path.join(dir, 'outside.txt'), `${OPENAI}\n`);
    writeFileSync(path.join(dir, 'pkg', 'inside.txt'), `x\n${AWS}\n`);
    commitAll(dir, 'both', 'outside.txt', 'pkg/inside.txt');
    const summary = await scanGitHistory(
      await resolveHistoryScan(path.join(dir, 'pkg')), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef,
    );
    expect(summary.hits.map((h) => [h.file, h.line, h.credentialType])).toEqual([['inside.txt', 2, 'AWS_ACCESS_KEY']]);
  });

  it('repository config cannot run a program or reshape the output the parser reads', async () => {
    const dir = freshDir();
    initThrowawayRepo(dir);
    const marker = path.join(dir, 'ran');
    const tool = path.join(dir, 'tool.sh');
    writeFileSync(tool, `#!/bin/sh\ntouch '${marker}'\n`);
    chmodSync(tool, 0o755);
    writeFileSync(path.join(dir, 'naïve "q".txt'), `${OPENAI}\n`);
    const root = commitAll(dir, 'root', 'naïve "q".txt');
    // Written after the commit, so only the scan's own git runs can trip it.
    const cfg = path.join(dir, '.git', 'config');
    for (const [k, v] of [
      ['diff.external', tool],
      ['core.fsmonitor', tool],
      ['diff.noprefix', 'true'],
      ['log.showRoot', 'false'],
      ['core.quotePath', 'false'],
      ['color.ui', 'always'],
      ['color.diff', 'always'],
      ['diff.renames', 'copies'],
    ]) {
      execFileSync('git', ['config', '--file', cfg, k, v], { env: gitFreeEnv() });
    }
    const summary = await scanGitHistory(await resolveHistoryScan(dir), CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef);
    expect(summary.hits).toEqual([{ commit: root, file: 'naïve "q".txt', line: 1, credentialType: 'OPENAI_API_KEY' }]);
    expect(existsSync(marker)).toBe(false);
  });

  it('an inherited GIT_DIR does not redirect the scan to another repository', () => {
    const saved = process.env.GIT_DIR;
    process.env.GIT_DIR = '/nonexistent/.git';
    try {
      expect(Object.keys(gitEnvironment()).some((k) => k.startsWith('GIT_'))).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = saved;
    }
  });
});

describe('refusals happen before any scanning', () => {
  it('a directory outside any work tree', async () => {
    const dir = freshDir();
    const err = await resolveHistoryScan(dir).catch((e) => e);
    expect(err).toBeInstanceOf(HistoryScanRefusal);
    expect(err.subject).toBe('target');
  });

  it.each([['-x'], ['--all'], [''], ['no-such-ref']])('--since %j', async (since) => {
    const { dir } = removedSecretRepo();
    const err = await resolveHistoryScan(dir, since).catch((e) => e);
    expect(err).toBeInstanceOf(HistoryScanRefusal);
    expect(err.subject).toBe('since');
  });
});

describe('the diff parser', () => {
  const parse = (text: string) => {
    const p = new HistoryDiffParser(CREDENTIAL_PATTERNS, hasCredentialOutsideEnvRef);
    for (const line of text.split('\n')) p.feed(line);
    return p;
  };
  const sha = 'a'.repeat(40);

  it('counts hunk lines, so an added line spelled like a header is content', () => {
    const p = parse([
      `\u0000${sha}`,
      '',
      'diff --git a/f b/f',
      '--- a/f',
      '+++ b/f',
      '@@ -3,0 +4,3 @@',
      '++++ b/elsewhere',
      '+@@ -1 +100 @@',
      `+k=${OPENAI}`,
    ].join('\n'));
    expect(p.hits).toEqual([{ commit: sha, file: 'f', line: 6, credentialType: 'OPENAI_API_KEY' }]);
  });

  it('a carriage return inside an added line does not split it', () => {
    const p = parse([`\u0000${sha}`, '+++ b/f', '@@ -0,0 +1,2 @@', '+a\rb', `+${OPENAI}`].join('\n'));
    expect(p.hits.map((h) => h.line)).toEqual([2]);
  });

  it('a removed line is never a hit, and a reference by name is not a value', () => {
    const p = parse([
      `\u0000${sha}`, '+++ b/f', '@@ -1,1 +1,1 @@', `-${OPENAI}`, '+token=${OPENAI_API_KEY}',
    ].join('\n'));
    expect(p.hits).toEqual([]);
  });

  it('decodes quoted paths', () => {
    expect(unquoteGitPath('"b/na\\303\\257ve \\"q\\".txt"')).toBe('b/naïve "q".txt');
    expect(unquoteGitPath('b/plain.txt')).toBe('b/plain.txt');
  });
});
