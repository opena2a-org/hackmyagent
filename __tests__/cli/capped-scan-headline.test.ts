/**
 * #358 — `secure` at a repository root printed `No security issues found`
 * for a tree it had not read in full. The semantic pass stops at a file cap
 * (`MAX_FILES_PER_SCAN` in `src/nanomind-core/scanner-bridge.ts`), so a
 * dot-directory such as `.github` can sit past the cap on a large tree while
 * a scan of that subdirectory alone reads it.
 *
 * The Observations block already qualified this ("No issues in what was
 * examined — but N stopped at a file cap"), but the headline above the score
 * still printed the green all-clear. This suite pins the headline to the same
 * measurement: over a capped clean tree it names what it examined, and under
 * the cap it still prints the all-clear, so the new branch cannot be
 * unconditional.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI; refuse to measure a stale binary.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');

/** More documents than the semantic pass compiles in one scan. */
const OVER_CAP = 210;
const UNDER_CAP = 3;

let base = '';
let home = '';

/** A tree with nothing to report except, optionally, its size. */
function cleanTree(name: string, docs: number): string {
  const dir = path.join(base, name);
  mkdirSync(path.join(dir, 'docs'), { recursive: true });
  mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
  writeFileSync(
    path.join(dir, 'package-lock.json'),
    JSON.stringify({
      name,
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: { '': { name, version: '1.0.0' } },
    }),
  );
  writeFileSync(
    path.join(dir, '.gitignore'),
    ['node_modules', '.env', '.env.*', '*.pem', '*.key', 'secrets.json', '*.p12', '.hackmyagent-backup/', ''].join('\n'),
  );
  writeFileSync(
    path.join(dir, '.github', 'workflows', 'ci.yml'),
    ['name: ci', 'on: [push]', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    steps:', '      - run: npm test', ''].join('\n'),
  );
  for (let i = 1; i <= docs; i++) {
    writeFileSync(path.join(dir, 'docs', `note-${i}.md`), `# Note ${i}\n\nPlain project documentation.\n`);
  }
  return dir;
}

function secure(dir: string, args: string[] = []) {
  const r = spawnSync('node', [CLI, 'secure', dir, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1' },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

beforeAll(() => {
  base = mkdtempSync(path.join(tmpdir(), 'hma-358-'));
  home = mkdtempSync(path.join(tmpdir(), 'hma-358-home-'));
});

afterAll(() => {
  if (base) rmSync(base, { recursive: true, force: true });
  if (home) rmSync(home, { recursive: true, force: true });
});

describe('#358 — the headline does not claim a clean tree the run did not read', { timeout: 600_000 }, () => {
  it.runIf(existsSync(CLI))('over the semantic cap: nothing found, and the headline says what was examined', () => {
    const dir = cleanTree('capped', OVER_CAP);

    const json = secure(dir, ['--json']);
    const doc = JSON.parse(json.stdout);
    // The scenario is a clean result over a capped pass; if either half stops
    // holding, the text assertions below would be measuring something else.
    expect(doc.coverage.semanticCompileSetTruncated).toBe(true);
    expect((doc.findings ?? []).filter((f: { passed?: boolean }) => !f.passed)).toEqual([]);

    const text = secure(dir);
    expect(text.status, text.stderr.slice(-2000)).toBe(0);
    expect(text.stdout).toMatch(/semantic capped at \d+/);
    expect(text.stdout).toContain('No issues in what was examined');
    expect(text.stdout).not.toContain('No security issues found');
  });

  it.runIf(existsSync(CLI))('under the cap: the same clean tree keeps the all-clear headline', () => {
    const dir = cleanTree('uncapped', UNDER_CAP);

    const json = secure(dir, ['--json']);
    const doc = JSON.parse(json.stdout);
    expect(doc.coverage.semanticCompileSetTruncated).toBe(false);
    expect((doc.findings ?? []).filter((f: { passed?: boolean }) => !f.passed)).toEqual([]);

    const text = secure(dir);
    expect(text.status, text.stderr.slice(-2000)).toBe(0);
    expect(text.stdout).not.toMatch(/semantic capped at/);
    expect(text.stdout).toContain('No security issues found');
  });
});
