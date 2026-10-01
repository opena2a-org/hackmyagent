/**
 * #294 — `secure --fix` names the governance file it rewrote in its fix summary.
 *
 * Reproduced on 0.33.2: a directory holding `package.json` and a 7-line
 * `SOUL.md` came out of `secure . --fix` with a 413-line `SOUL.md`. The
 * harden-soul write was reported on stderr, but the stdout summary read
 * `Fixed 1 issue (1 verified): [GIT-001] .gitignore`, and Next Steps still
 * told the reader to run `harden-soul .`, which the run had just applied.
 *
 * The summary now carries the governance write as its own line, says the
 * report was measured before it, and Next Steps drops the step already taken.
 */
import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');
const SOUL = '# Agent\n\nYou are a helpful assistant.\n\n## Rules\n- Be nice.\n- Help users.\n';
const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function fixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-gov-summary-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'package.json'), '{"name":"soul-demo","version":"1.0.0"}\n');
  writeFileSync(join(dir, 'SOUL.md'), SOUL);
  return dir;
}

const secure = (dir: string, ...args: string[]) =>
  spawnSync('node', [CLI, 'secure', '.', ...args], {
    cwd: dir, encoding: 'utf8', timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1' },
  });

describe('#294 secure --fix reports the governance file it rewrote', () => {
  it('lists the harden-soul write in the stdout summary and drops the step already taken', () => {
    const dir = fixture();
    const run = secure(dir, '--fix');
    const after = readFileSync(join(dir, 'SOUL.md'), 'utf8');
    // Non-vacuity: the governance auto-fix must actually have written.
    expect(after.length, 'harden-soul did not run; this test is measuring nothing').toBeGreaterThan(SOUL.length);
    expect(run.stderr).toContain('Governance auto-fix: harden-soul applied');

    expect(run.stdout).toMatch(/Governance file rewritten: SOUL\.md - harden-soul added \d+ sections?/);
    expect(run.stdout).toContain('The findings and score above were measured before this write.');
    expect(run.stdout).toContain('Run `hackmyagent secure .` to score the hardened file.');
    expect(run.stdout).not.toContain('Auto-fix governance:');
  });

  it('keeps the Next Steps hint when no governance write happened', () => {
    const dir = fixture();
    const run = secure(dir);
    expect(readFileSync(join(dir, 'SOUL.md'), 'utf8')).toBe(SOUL);
    expect(run.stdout).toContain('Auto-fix governance:');
    expect(run.stdout).not.toContain('Governance file rewritten:');
  });
});
