/**
 * #740 — `check <local dir>` runs the static check suite.
 *
 * `hackmyagent check <dir> --offline` on a tree whose `.claude/settings.json`
 * held a plaintext API key reported `Quick scan 96/100`, `Usable with
 * caveats`, exit 0, with the note `318 static not run (quick scan)`. The user
 * asked for a verdict on a directory they pointed at and got a number produced
 * without running the checks that read the credential.
 *
 * A local directory target now goes through the same pipeline `secure` runs —
 * static suite plus the semantic pass, scored the same way — so the verdict
 * is computed from the checks that read the tree, and the machine channel
 * discloses executed checks rather than a `quick-scan` mode with a count of
 * checks that did not run.
 *
 * Two edges of the same arm are held here too. A lone FILE target is scanned
 * in isolation, as `secure <file>` scans it, so the verdict on `skill.md`
 * cannot carry the findings of a sibling the user did not name. And
 * `--no-scan` (registry only, skip the download and scan) has nothing to
 * query for a local path, so it is refused rather than silently running the
 * suite.
 *
 * The fixtures are built at test time. Keys are assembled from pieces so no
 * tracked line carries the provider-token shape (HMA-16).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const EXIT_FAIL = 1;
const EXIT_UNMEASURED = 2;

let root: string;
let dir: string;
let fileTree: string;
const homes: string[] = [];

function run(args: string[], cwd?: string) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  homes.push(home);
  const res = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
    },
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}`, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

function json(args: string[]) {
  const res = run([...args, '--json']);
  return { status: res.status, body: JSON.parse(res.stdout) as any, stderr: res.stderr };
}

/** The issue's reproduce line: a vendor-prefixed key of 60 trailing bytes. */
function key(): string {
  return ['sk-ant', '-api03-', 'a'.repeat(60)].join('');
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-740-'));
  dir = path.join(root, 'tree');
  fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, '.claude', 'settings.json'),
    JSON.stringify({ env: { ANTHROPIC_API_KEY: key() } }) + '\n',
  );
  // A clean skill beside a sibling that carries a key.
  fileTree = path.join(root, 'file-target');
  fs.mkdirSync(fileTree, { recursive: true });
  fs.writeFileSync(
    path.join(fileTree, 'skill.md'),
    '---\nname: tidy-skill\ndescription: Formats markdown tables.\n---\n\nRun the formatter on the current file.\n',
  );
  fs.writeFileSync(path.join(fileTree, '.env'), `ANTHROPIC_API_KEY=${key()}\n`);
});

afterAll(() => {
  for (const p of [root, ...homes]) {
    try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

describe('#740 check <local dir> runs the static checks', { timeout: 300_000 }, () => {
  it('--offline: the static credential check reads the key and the run fails', () => {
    const { status, out } = run(['check', dir, '--offline']);
    expect(status).toBe(EXIT_FAIL);
    // The defect's own words. A local directory the user pointed at is not
    // a quick scan.
    expect(out).not.toMatch(/static not run/);
    expect(out).not.toMatch(/^\s+Quick scan\s+━/m);
    expect(out).toMatch(/^\s+Security\s+━+\s+\d+\/100/m);
    // The static check `secure` reports on the same tree, by name and path.
    expect(out).toContain('Exposed Credential');
    expect(out).toContain('.claude/settings.json');
    // The Checks line counts executed groups, as `secure` prints it.
    expect(out).toMatch(/\d+ static declared · \d+ of \d+ check groups ran/);
  });

  it('--offline --json: same verdict, the static finding in details, executed checks disclosed', () => {
    const { status, body } = json(['check', dir, '--offline']);
    expect(status).toBe(EXIT_FAIL);
    expect(body.type).toBe('local-scan');
    expect(body.risk).toBe('critical');
    expect(body.measured).toBe(true);
    expect(typeof body.score).toBe('number');
    const cred = (body.details ?? []).filter((f: any) => f.checkId === 'CRED-001');
    expect(cred).toHaveLength(1);
    expect(cred[0].file).toBe('.claude/settings.json');
    // No quick-scan disclosure: the suite ran, so nothing is "not run".
    expect(body.coverage.mode).toBeUndefined();
    expect(body.coverage.staticChecksNotRun).toBeUndefined();
    expect(body.coverage.measured).toBe(true);
    expect(body.coverage.unit).toBe('file');
    expect(body.coverage.examined).toBeGreaterThan(0);
    expect(Array.isArray(body.coverage.executions)).toBe(true);
    expect(body.coverage.executions.length).toBeGreaterThan(0);
  });

  it('scores the tree the way secure scores it', () => {
    const check = json(['check', dir, '--offline']);
    const secure = json(['secure', dir, '--no-registry']);
    expect(check.body.score).toBe(secure.body.score);
    const ids = (arr: any[]) => arr.filter((f) => !f.passed).map((f) => f.checkId).sort();
    expect(ids(check.body.details ?? [])).toEqual(ids(secure.body.findings ?? []));
  });

  it('without --offline the local arm takes the same path: static checks run', () => {
    // The local-path arm never queries the Registry, so this spawn is as
    // offline as the flagged one; the flag only names the intent.
    const { status, out } = run(['check', dir]);
    expect(status).toBe(EXIT_FAIL);
    expect(out).not.toMatch(/static not run/);
    expect(out).toContain('Exposed Credential');
  });
});

describe('#740 a lone file target is scanned in isolation, as secure scans it', { timeout: 300_000 }, () => {
  it('check <dir>/skill.md reports nothing from the sibling .env', () => {
    const { status, body } = json(['check', path.join(fileTree, 'skill.md'), '--offline']);
    expect(body.measured).toBe(true);
    const files = (body.details ?? []).map((f: any) => f.file);
    expect(files.some((f: string) => /(^|\/)\.env$/.test(f))).toBe(false);
    expect((body.details ?? []).some((f: any) => f.checkId === 'CRED-001')).toBe(false);
    expect(['low', 'medium']).toContain(body.risk);
    expect(status).not.toBe(EXIT_FAIL);
  });

  it('check <dir> reports the sibling .env', () => {
    const { status, body } = json(['check', fileTree, '--offline']);
    expect(status).toBe(EXIT_FAIL);
    const cred = (body.details ?? []).filter((f: any) => f.checkId === 'CRED-001');
    expect(cred).toHaveLength(1);
    expect(cred[0].file).toBe('.env');
  });
});

describe('#740 --no-scan is refused on a local path', { timeout: 300_000 }, () => {
  // The band word and separator are the exit-2 renderer's; the words after
  // them are this refusal's, and the cited command carries the CLI prefix.
  const NOTICE = /--no-scan skips the scan, and a local path has no registry record to query instead\. Run hackmyagent check \S+ without --no-scan\./;
  const LINE = /^NOT MEASURED — --no-scan skips the scan, and a local path has no registry record to query instead\. Run hackmyagent check \S+ without --no-scan\.$/m;

  it('text: one stderr line, no scan, exit 2', () => {
    const { status, stdout, stderr } = run(['check', dir, '--no-scan']);
    expect(status).toBe(EXIT_UNMEASURED);
    expect(stderr).toMatch(LINE);
    expect(stderr.trim().split('\n')).toHaveLength(1);
    expect(stdout).toBe('');
  });

  it('--json: the same refusal, unmeasured, exit 2', () => {
    const { status, body, stderr } = json(['check', dir, '--no-scan']);
    expect(status).toBe(EXIT_UNMEASURED);
    expect(stderr).toMatch(LINE);
    expect(body.type).toBe('local-path');
    expect(body.coverage.measured).toBe(false);
    expect(body.coverage.examined).toBe(0);
    expect(body.coverage.reason).toBe('scan-skipped');
    expect(body.error).toMatch(NOTICE);
    expect(body.risk).toBeUndefined();
    expect(body.score).toBeUndefined();
  });
});

describe('#740 every local path spelling prints the auto-fix next step', { timeout: 300_000 }, () => {
  it('a bare-relative path, spawned from its parent, prints `secure <path> --fix`', () => {
    // `./tree` and the absolute path printed the line; `tree` did not, because
    // the next-steps renderer decided "local" from the spelling of the target
    // as typed rather than from the arm that produced the findings.
    const { status, out } = run(['check', 'tree', '--offline'], root);
    expect(status).toBe(EXIT_FAIL);
    expect(out).toMatch(/Auto-fix all issues:\s+hackmyagent secure tree --fix/);
  });
});

describe('an existing, readable, empty directory is a measured absence, as secure reads it', { timeout: 300_000 }, () => {
  // Ruled 2026-09-15: the scanner walked the directory and ran its checks
  // over it, so the run has evidence (a recorded absence), the same reading
  // `secure` gives the same tree. 0.33.0 exited 2 here with NOT MEASURED.
  it('text: a report with a score, no banner, exit 0', () => {
    const empty = fs.mkdtempSync(path.join(root, 'empty-'));
    const { status, stdout, stderr } = run(['check', empty, '--offline']);
    expect(status).toBe(0);
    expect(stdout).toMatch(/\d+\/100/);
    expect(stderr).not.toContain('NOT MEASURED');
  });

  it('--json: measured, a non-failing risk band, the score secure gives the same tree, exit 0', () => {
    const empty = fs.mkdtempSync(path.join(root, 'empty-json-'));
    const check = json(['check', empty, '--offline']);
    const secure = json(['secure', empty, '--no-registry']);
    expect(check.status).toBe(0);
    expect(check.body.measured).toBe(true);
    // The band follows the absence findings a bare tree carries (DEP-001,
    // SANDBOX-001), so it is medium or low, never null and never failing.
    expect(['low', 'medium']).toContain(check.body.risk);
    expect(typeof check.body.score).toBe('number');
    expect(check.body.score).toBe(secure.body.score);
    expect(check.body.coverage.measured).toBe(true);
    expect(check.body.coverage.examined).toBe(0);
    expect(check.body.coverage.reason).toBeUndefined();
    expect(check.body.coverage.executions.length).toBeGreaterThan(0);
  });

  it('a directory whose only file cannot be read stays unmeasured: banner, Verify, pointer, exit 2', () => {
    if (typeof process.getuid === 'function' && process.getuid() === 0) return;
    const dir = fs.mkdtempSync(path.join(root, 'unread-'));
    const file = path.join(dir, 'config.json');
    fs.writeFileSync(file, '{}\n');
    fs.chmodSync(file, 0o000);
    try {
      const { status, stderr } = run(['check', dir, '--offline']);
      expect(status).toBe(EXIT_UNMEASURED);
      expect(stderr).toContain('NOT MEASURED');
      expect(stderr).toMatch(/^  Verify: ls -la /m);
      expect(stderr).toContain('Point check at the directory that holds the project files (package.json, .claude/, mcp.json, SOUL.md).');
      const { body } = json(['check', dir, '--offline']);
      expect(body.measured).toBe(false);
      expect(body.coverage.reason).toBe('target-unreadable');
    } finally {
      fs.chmodSync(file, 0o600);
    }
  });
});
