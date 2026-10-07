/**
 * #609 — the secure-openclaw Checks line partitions its total.
 *
 * Checks that fix what they found report `passed: <check>Fixed`, so counting
 * `passed` as `f.passed` put a confirmed fix under both `fixed` and `passed`:
 * measured on this fixture, `Checks: 7 total | 5 issues | 2 fixed | 2 passed`,
 * nine for seven. `issues`, `fixed` and `passed` must sum to the total on the
 * text line and in `--json`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

/**
 * The issue's fixture: an unsigned skill with a wildcard and a system-path grant.
 * SKILL-004 rewrites its wildcard, and the re-scan still finds `/etc/passwd`, so
 * that fix is disproved. The second skill grants only the wildcard, so its
 * SKILL-004 fix is confirmed: SKILL-001 no longer fixes anything (#269), and
 * without this skill the run would have no confirmed fix to count.
 */
function fixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-609-openclaw-'));
  mkdirSync(path.join(dir, 'skills', 'demo'), { recursive: true });
  writeFileSync(
    path.join(dir, 'skills', 'demo', 'SKILL.md'),
    '---\nname: demo\ndescription: demo skill\n---\n# Demo\n\nfilesystem: * and filesystem: /etc/passwd\n',
  );
  mkdirSync(path.join(dir, 'skills', 'wildcard'), { recursive: true });
  writeFileSync(
    path.join(dir, 'skills', 'wildcard', 'SKILL.md'),
    '---\nname: wildcard\ndescription: wildcard skill\n---\n# Wildcard\n\nfilesystem: *\n',
  );
  return dir;
}

function run(dir: string, extra: string[] = []) {
  const home = mkdtempSync(path.join(tmpdir(), 'hma-609-home-'));
  const r = spawnSync(process.execPath, [CLI, 'secure-openclaw', '--fix', dir, ...extra], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...process.env,
      HOME: home,
      OPENA2A_HOME: path.join(home, '.opena2a'),
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
      FORCE_COLOR: '0',
    },
  });
  // eslint-disable-next-line no-control-regex
  const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
  return { status: r.status, stdout: strip(r.stdout ?? '') };
}

describe('#609 secure-openclaw --fix: issues, fixed and passed partition the total', () => {
  it('text: the Checks line sums to its total, with at least one confirmed fix', () => {
    const r = run(fixture());
    const line = r.stdout.split('\n').find((l) => l.startsWith('Checks: '));
    expect(line, r.stdout).toBeDefined();
    const m = line!.match(/^Checks: (\d+) total \| (\d+) issues? \| (\d+) fixed \| (\d+) passed$/);
    expect(m, line).not.toBeNull();
    const [total, issues, fixed, passed] = m!.slice(1).map(Number);
    // Not vacuous: the fixture reaches a check that fixes what it found.
    expect(fixed).toBeGreaterThanOrEqual(1);
    expect(issues + fixed + passed).toBe(total);
  }, 180_000);

  it('--json: the same partition on totalChecks', () => {
    const r = run(fixture(), ['--json']);
    const json = JSON.parse(r.stdout);
    expect(json.fixed).toBeGreaterThanOrEqual(1);
    expect(json.issues + json.fixed + json.passed).toBe(json.totalChecks);
    // A confirmed fix is not also a pass.
    const fixedIds = new Set(
      (json.findings as Array<{ checkId: string; fixed?: boolean; fixVerified?: boolean }>)
        .filter((f) => f.fixed && f.fixVerified !== false)
        .map((f) => f.checkId),
    );
    expect(fixedIds.size).toBeGreaterThanOrEqual(1);
  }, 180_000);
});
