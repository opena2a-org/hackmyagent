/**
 * #610 — every `--fix` channel that wrote a backup says where it is.
 *
 * Three surfaces rewrote the tree (or added a backup run directory to it) and
 * ended without the `Backup created:` disclosure:
 *
 * 1. `secure-openclaw --fix` on a target with no OpenClaw check to evaluate:
 *    the scanner had already written a GIT-001 `.gitignore` and the backup,
 *    and the NOT MEASURED arm returned above the disclosure.
 * 2. `secure-openclaw --fix --json`: the hand-built document had no
 *    `backupPath`, while `secure --format json` carries it.
 * 3. `secure --fix` that attempted nothing: the disclosure was nested under the
 *    attempt count, so a second run on a hardened tree added a run directory
 *    silently.
 *
 * The rule each case asserts: if a backup run directory exists after the run
 * that did not exist before it, the run's output names it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

function runs(dir: string): string[] {
  const base = path.join(dir, '.hackmyagent-backup');
  return existsSync(base) ? readdirSync(base).filter((e) => !e.startsWith('.')) : [];
}

function hma(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const home = mkdtempSync(path.join(tmpdir(), 'hma-610-home-'));
  try {
    const res = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, HOME: home, OPENA2A_HOME: home, NO_COLOR: '1' },
    });
    // eslint-disable-next-line no-control-regex
    const strip = (s: string | null): string => (s ?? '').replace(/\x1b\[[0-9;]*m/g, '');
    return { stdout: strip(res.stdout), stderr: strip(res.stderr), status: res.status };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

function skillTree(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-610-'));
  mkdirSync(path.join(dir, 'skills', 'demo'), { recursive: true });
  writeFileSync(path.join(dir, 'skills', 'demo', 'SKILL.md'), '---\nname: demo\ndescription: d\n---\n# D\n');
  return dir;
}

describe.skipIf(process.platform === 'win32' || !existsSync(CLI))('#610 a --fix run that wrote a backup says so', () => {
  beforeAll(assertDistFreshIfPresent);

  it('secure-openclaw --fix, unmeasured arm: names the backup it wrote', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hma-610-empty-'));
    try {
      const out = hma(['secure-openclaw', '--fix', dir]);
      const written = runs(dir);
      expect(out.status).toBe(2);
      expect(`${out.stdout}${out.stderr}`).toMatch(/NOT MEASURED/);
      expect(written).toHaveLength(1);
      expect(out.stdout).toContain(`Backup created:`);
      expect(out.stdout).toContain(written[0]);
      expect(out.stdout).toMatch(/To rollback: \S+ rollback /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('secure-openclaw --fix --json: carries backupPath when a backup was written', () => {
    const dir = skillTree();
    try {
      const out = hma(['secure-openclaw', '--fix', '--json', dir]);
      const doc = JSON.parse(out.stdout) as { backupPath?: string };
      const written = runs(dir);
      expect(written).toHaveLength(1);
      expect(typeof doc.backupPath).toBe('string');
      expect(doc.backupPath).toContain(written[0]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // #862 — both benchmark arms of `secure` returned above the disclosure, so
  // a `-b oasb-1 --fix` run wrote `.gitignore` and a backup run directory and
  // named neither.
  it.each(['oasb-1', 'oasb-2'])('secure -b %s --fix, text report: names the backup it wrote', (benchmark) => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hma-862-'));
    try {
      writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}\n');
      const out = hma(['secure', dir, '-b', benchmark, '--fix']);
      const written = runs(dir);
      expect(written).toHaveLength(1);
      expect(out.stdout).toContain('Backup created:');
      expect(out.stdout).toContain(written[0]);
      expect(out.stdout).toMatch(/Something wrong\? Run `\S+ rollback /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('secure --fix that attempted nothing: names the run directory it added', () => {
    const dir = skillTree();
    try {
      hma(['secure', '--fix', dir]);
      const before = runs(dir);
      const out = hma(['secure', '--fix', dir]);
      const added = runs(dir).filter((r) => !before.includes(r));
      expect(added).toHaveLength(1);
      expect(out.stdout).toContain('Backup created:');
      expect(out.stdout).toContain(added[0]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
