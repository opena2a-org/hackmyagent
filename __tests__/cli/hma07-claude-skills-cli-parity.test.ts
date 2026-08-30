/**
 * HMA-07.AC1 — the `.claude/skills` twin parity holds through the CLI entry too.
 *
 * `HardeningScanner.scan` is one direction into the static suite; `hackmyagent
 * secure <dir>` is the one users take. A fix that lands in the scanner but is
 * filtered, project-type-gated or noise-floored out of the CLI report is not a
 * fix a user can see, and this repo has shipped exactly that shape of
 * disagreement before (the single-file target work, #220 / audit 2026-06-01).
 *
 * Spawn-based, so it is gated on a built `dist/cli.js` exactly like the other
 * spawn suites in this directory. `assertDistFreshIfPresent` (#285) is what
 * stops it from measuring a stale binary and reporting a pass.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { MALICIOUS_SKILL } from '../helpers/hma07-skill-fixtures';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const canRun = () => existsSync(CLI);

function write(filePath: string, content: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, content);
}

function failingSkillIds(target: string): string[] {
  const r = spawnSync('node', [CLI, 'secure', target, '--json', '--ci'], {
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
  });
  const data = JSON.parse((r.stdout || '').trim()) as {
    findings?: Array<{ checkId: string; passed: boolean }>;
  };
  return [...new Set(
    (data.findings || [])
      .filter(f => !f.passed && f.checkId?.startsWith('SKILL-'))
      .map(f => f.checkId),
  )].sort();
}

describe('HMA-07.AC1 .claude/skills through the CLI entry', () => {
  it('HMA-07.AC1 secure <dir> reports the same failing SKILL-* checkIds for a .claude/skills skill as for its skills/ twin', () => {
    if (!canRun()) return;
    const root = mkdtempSync(join(tmpdir(), 'hma07-cli-parity-'));
    const plainRoot = join(root, 'plain');
    const claudeRoot = join(root, 'claude');
    write(join(plainRoot, 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);
    write(join(claudeRoot, '.claude', 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);

    const plainIds = failingSkillIds(plainRoot);
    const claudeIds = failingSkillIds(claudeRoot);

    // Guard: without this the parity assertion passes on two empty sets.
    expect(plainIds.length).toBeGreaterThan(0);
    expect(claudeIds).toEqual(plainIds);
  });
});
