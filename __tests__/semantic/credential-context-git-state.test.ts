/**
 * #208 regression: .env credential severity must consult git tracking state.
 *
 * Each test builds a real temp git repo, drops a `.env` with a fake API key,
 * runs the StructuralAnalyzer, and asserts the SEM-CRED-002 finding has the
 * right severity for that tracking state. Real `git` is invoked (no mocks)
 * to match production behavior end-to-end.
 *
 * Severity table (from triage):
 *   tracked OR has-add-history       -> HIGH (unchanged)
 *   not a git repo                   -> HIGH (safe default, can't verify)
 *   gitignored, never tracked        -> MEDIUM (local-only exposure)
 *   on disk, untracked, not ignored  -> MEDIUM (at risk of accidental commit)
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync, linkSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StructuralAnalyzer } from '../../src/semantic/structural';

const FAKE_ENV_BODY = 'ANTHROPIC_API_KEY=sk-ant-FAKE1234567890abcdefghijklmnop\n';

function git(cwd: string, ...args: string[]): void {
  // Strip ambient git env. When this suite runs inside a git hook (e.g. the
  // pre-push hook running `npm test`), git exports GIT_DIR / GIT_WORK_TREE /
  // GIT_INDEX_FILE pointing at the REAL repo. Inheriting them makes these
  // temp-dir commits land in the actual repo (observed: the pre-push hook's
  // test run committed `.env` / `secrets/real.env` onto the working branch).
  // cwd alone is not enough — GIT_DIR overrides cwd.
  const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  const r = spawnSync('git', args, {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf-8',
  });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed (${r.status}): ${r.stderr}`);
  }
}

function findEnvCred(findings: { id: string; file: string }[]): { id: string; file: string; severity: string; rationale: string; recommendation: string } | undefined {
  return findings.find((f) => f.id === 'SEM-CRED-002' && f.file === '.env') as unknown as ReturnType<typeof findEnvCred>;
}

describe('#208: .env credential severity by git state', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'hma-208-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('tracked .env -> HIGH (gitignore does not untrack)', async () => {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);
    git(dir, 'add', '.env');
    git(dir, 'commit', '-q', '-m', 'oops committed .env');

    // Add to gitignore AFTER tracking; should still fire HIGH.
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'gitignore .env (still tracked)');

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('high');
  });

  it('gitignored, never tracked -> MEDIUM (local-only, not in version control)', async () => {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'gitignore .env from day 1');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('medium');
    expect(env!.rationale).not.toMatch(/If this file is committed/);
    expect(env!.recommendation).toMatch(/opena2a protect/);
  });

  it('gitignored but with add-history -> HIGH (rm --cached does not erase history)', async () => {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);
    git(dir, 'add', '.env');
    git(dir, 'commit', '-q', '-m', 'commit .env (leaked once)');
    git(dir, 'rm', '--cached', '-q', '.env');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'untrack .env, but reflog still has it');
    // .env is still on disk
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('high');
  });

  it('not a git repo -> HIGH (safe default, can\'t verify)', async () => {
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('high');
  });

  it('untracked, not gitignored -> MEDIUM (at risk of accidental commit)', async () => {
    git(dir, 'init', '-q');
    // Commit an unrelated file to establish HEAD
    writeFileSync(join(dir, 'README.md'), '# t\n');
    git(dir, 'add', 'README.md');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('medium');
  });

  it('URL password in gitignored .env stays HIGH (#208 explicit out-of-scope)', async () => {
    // Triage said URL-embedded credentials leak via proxies/logs/process
    // listings even when the file is gitignored. SEM-CRED-001 stays HIGH.
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'gitignore .env');
    writeFileSync(join(dir, '.env'), 'DATABASE_URL=postgres://u:realisticpassword@host/db\n');

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const url = findings.find((f) => f.id === 'SEM-CRED-001');
    expect(url, 'expected SEM-CRED-001 (URL password)').toBeDefined();
    expect(url!.severity).toBe('high');
  });

  it('symlinked .env -> tracked target stays HIGH (round-1 bypass)', async () => {
    git(dir, 'init', '-q');
    mkdirSync(join(dir, 'secrets'));
    writeFileSync(join(dir, 'secrets', 'real.env'), FAKE_ENV_BODY);
    writeFileSync(join(dir, '.gitignore'), '/.env\n');
    git(dir, 'add', '.gitignore', 'secrets/real.env');
    git(dir, 'commit', '-q', '-m', 'tracked real.env, link to follow');
    symlinkSync('secrets/real.env', join(dir, '.env'));

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 via the .env symlink').toBeDefined();
    // The link target is tracked -> the secret IS in version control -> HIGH.
    expect(env!.severity).toBe('high');
  });

  it('deleted-branch add-history -> HIGH via reflog (round-1 bypass)', async () => {
    git(dir, 'init', '-q', '--initial-branch=main');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'init');
    git(dir, 'checkout', '-q', '-b', 'draft');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);
    git(dir, 'add', '-f', '.env');
    git(dir, 'commit', '-q', '-m', 'leaked-once on draft');
    git(dir, 'checkout', '-q', 'main');
    git(dir, 'branch', '-D', 'draft');
    // .env on disk again with current secret. The deleted branch's add is
    // unreachable from --all but recoverable via reflog.
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('high');
  });

  it('untracked + not gitignored: rationale tells the truth (no false "gitignored" claim)', async () => {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'README.md'), '# t\n');
    git(dir, 'add', 'README.md');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on .env').toBeDefined();
    expect(env!.severity).toBe('medium');
    // Must NOT claim "is gitignored" (it isn't); MUST acknowledge the file
    // is on track for accidental commit.
    expect(env!.rationale).not.toMatch(/is gitignored/);
    expect(env!.rationale).toMatch(/not (gitignored|in version control)|NOT gitignored/);
    expect(env!.recommendation).toMatch(/\.gitignore/);
  });

  it('.env.local untracked+gitignored downgrades just like .env', async () => {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.gitignore'), '.env*\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(join(dir, '.env.local'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findings.find((f) => f.id === 'SEM-CRED-002' && f.file === '.env.local');
    expect(env, 'expected SEM-CRED-002 on .env.local').toBeDefined();
    expect(env!.severity).toBe('medium');
  });

  it('internal consistency: mixed-format secrets in same gitignored .env all downgrade', async () => {
    // Round-1 found that JSON/YAML-pattern emit sites were hardcoding HIGH
    // while the .env-format emit site downgraded, producing self-contradictory
    // findings on adjacent lines of the same file.
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(
      join(dir, '.env'),
      'ANTHROPIC_API_KEY=sk-ant-FAKE1234567890abcdefghijklmnop\n' +
        '"api_key": "sk-proj-FAKEabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu"\n',
    );

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const envFindings = findings.filter((f) => f.id === 'SEM-CRED-002' && f.file === '.env');
    expect(envFindings.length, 'expected one finding per format match').toBeGreaterThanOrEqual(2);
    for (const f of envFindings) {
      expect(f.severity, `inconsistent severity on .env:${f.line}`).toBe('medium');
    }
  });

  it('absolute-path symlink to tracked target stays HIGH (round-2 path-resolution bypass)', async () => {
    // Round 2 found that path.resolve(rootDir) does not follow symlinks,
    // so on macOS where /var/folders is a link to /private/var/folders,
    // a symlink with an ABSOLUTE-path target produced an out-of-tree
    // path.relative() result and slipped through.
    git(dir, 'init', '-q');
    mkdirSync(join(dir, 'secrets'));
    writeFileSync(join(dir, 'secrets', 'real.env'), FAKE_ENV_BODY);
    writeFileSync(join(dir, '.gitignore'), '/.env\n');
    git(dir, 'add', '.gitignore', 'secrets/real.env');
    git(dir, 'commit', '-q', '-m', 'tracked real.env');
    // ABSOLUTE-path symlink target (realpath form -- the macOS bug case).
    const absTarget = realpathSync(join(dir, 'secrets', 'real.env'));
    symlinkSync(absTarget, join(dir, '.env'));

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 via the .env symlink').toBeDefined();
    expect(env!.severity).toBe('high');
  });

  it('out-of-tree symlink target keeps HIGH (cannot verify tracking)', async () => {
    // .env -> outside-repo file. We have no way to query that file's
    // tracking state via this repo's git; default to HIGH.
    const outside = mkdtempSync(join(tmpdir(), 'hma-208-outside-'));
    try {
      writeFileSync(join(outside, 'real.env'), FAKE_ENV_BODY);
      git(dir, 'init', '-q');
      writeFileSync(join(dir, '.gitignore'), '/.env\n');
      git(dir, 'add', '.gitignore');
      git(dir, 'commit', '-q', '-m', 'init');
      symlinkSync(join(outside, 'real.env'), join(dir, '.env'));

      const analyzer = new StructuralAnalyzer();
      const findings = await analyzer.analyze(dir);
      const env = findEnvCred(findings);
      expect(env, 'expected SEM-CRED-002 via the .env symlink').toBeDefined();
      expect(env!.severity).toBe('high');
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('hardlinked .env stays HIGH (round-2 hardlink bypass)', async () => {
    // ln (not ln -s) shares the inode; lstat reports a regular file with
    // nlink > 1. We default HIGH because we can't cheaply prove the
    // other path holding the same bytes isn't tracked.
    git(dir, 'init', '-q');
    mkdirSync(join(dir, 'secrets'));
    writeFileSync(join(dir, 'secrets', 'real.env'), FAKE_ENV_BODY);
    writeFileSync(join(dir, '.gitignore'), '/.env\n');
    git(dir, 'add', '.gitignore', 'secrets/real.env');
    git(dir, 'commit', '-q', '-m', 'tracked real.env');
    linkSync(join(dir, 'secrets', 'real.env'), join(dir, '.env'));

    const analyzer = new StructuralAnalyzer();
    const findings = await analyzer.analyze(dir);
    const env = findEnvCred(findings);
    expect(env, 'expected SEM-CRED-002 on hardlinked .env').toBeDefined();
    expect(env!.severity).toBe('high');
    // Round-3: wording must explain hardlink, not parrot "Ensure .env is
    // in .gitignore" (which is already satisfied here).
    expect(env!.rationale).toMatch(/hardlink|shares its inode/i);
    expect(env!.recommendation).toMatch(/find .* -inum|readlink/);
  });

  it('out-of-tree symlink wording calls out the link target (round-3 CISO Rule 11)', async () => {
    const outside = mkdtempSync(join(tmpdir(), 'hma-208-outside-r3-'));
    try {
      writeFileSync(join(outside, 'real.env'), FAKE_ENV_BODY);
      git(dir, 'init', '-q');
      writeFileSync(join(dir, '.gitignore'), '/.env\n');
      git(dir, 'add', '.gitignore');
      git(dir, 'commit', '-q', '-m', 'init');
      symlinkSync(join(outside, 'real.env'), join(dir, '.env'));

      const analyzer = new StructuralAnalyzer();
      const findings = await analyzer.analyze(dir);
      const env = findEnvCred(findings);
      expect(env, 'expected SEM-CRED-002 via the .env symlink').toBeDefined();
      expect(env!.severity).toBe('high');
      expect(env!.rationale).toMatch(/outside this repo|symlink/);
      expect(env!.recommendation).toMatch(/readlink/);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('stale-cache regression: re-using StructuralAnalyzer reflects new git state', async () => {
    // Round-1 flagged a process-lifetime module cache. Build, scan, then
    // change tracking state, then scan AGAIN with the same analyzer instance.
    git(dir, 'init', '-q');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    git(dir, 'add', '.gitignore');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(join(dir, '.env'), FAKE_ENV_BODY);

    const analyzer = new StructuralAnalyzer();
    const first = await analyzer.analyze(dir);
    const firstEnv = findEnvCred(first);
    expect(firstEnv!.severity).toBe('medium');

    // Now commit .env (force, since it's gitignored). Severity must flip to HIGH.
    git(dir, 'add', '-f', '.env');
    git(dir, 'commit', '-q', '-m', 'oops committed .env');

    const second = await analyzer.analyze(dir);
    const secondEnv = findEnvCred(second);
    expect(secondEnv!.severity, 'stale cache served MEDIUM after .env became tracked').toBe('high');
  });
});
