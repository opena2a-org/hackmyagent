/**
 * #274 — the deprecated `secure-openclaw` arm on a run whose ONLY attempted fix
 * was disproved by the verification pass (`fixed: true, fixVerified: false`).
 *
 * Two properties, measured through the real CLI on a tree the run rewrites:
 *
 * 1. The counts line and `--json` count a fix only when it is confirmed, so the
 *    disproved attempt reads `0 fixed` and is listed under Findings ("Auto-fix
 *    did not resolve this"), never under Auto-Remediation Applied.
 * 2. The recoverability disclosure keys on the WRITE, not on the confirmed
 *    count: the run rewrote SKILL.md and created a backup, so "Backup created:"
 *    and the rollback command print even though nothing was confirmed. The
 *    first cut of the #274 change gated those lines on the confirmed count and
 *    printed neither for exactly this run (the review round caught it).
 *
 * The fixture reaches the branch by construction: SKILL-004's auto-fix rewrites
 * `filesystem: *` to `filesystem:./`, the re-scan still matches `/etc/passwd`
 * on the same line, so the attempt is disproved; the guard comment is
 * pre-signed with the hash of the post-fix body so the signature check does not
 * add a second attempt. Both cells assert the rewrite and the backup exist
 * BEFORE the property, so a fixture that stops reaching the branch fails loudly
 * instead of passing on a run that attempted nothing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');

const POST_FIX_BODY = '---\nname: demo\ndescription: demo skill\n---\n# Demo\n\nfilesystem:./ and filesystem: /etc/passwd\n\n';
const PRE_FIX_LINE_7 = 'filesystem: * and filesystem: /etc/passwd';
const POST_FIX_LINE_7 = 'filesystem:./ and filesystem: /etc/passwd';

function fixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-274-openclaw-'));
  mkdirSync(path.join(dir, 'skills', 'demo'), { recursive: true });
  const hash = createHash('sha256').update(POST_FIX_BODY.replace(/\n$/, '')).digest('hex');
  writeFileSync(
    path.join(dir, 'skills', 'demo', 'SKILL.md'),
    `---\nname: demo\ndescription: demo skill\n---\n# Demo\n\n${PRE_FIX_LINE_7}\n\n` +
      `<!-- opena2a-guard hash="sha256:${hash}" signed="2026-08-20T00:00:00.000Z" -->`,
  );
  return dir;
}

function run(dir: string, extra: string[] = []) {
  const home = mkdtempSync(path.join(tmpdir(), 'hma-274-home-'));
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
  return { status: r.status, stdout: strip(r.stdout ?? ''), stderr: strip(r.stderr ?? '') };
}

/** The fixture must have reached the disproved-attempt branch, or nothing below measures anything. */
function assertTreeWasRewritten(dir: string) {
  const line7 = readFileSync(path.join(dir, 'skills', 'demo', 'SKILL.md'), 'utf8').split('\n')[6];
  expect(line7, 'fixture no longer reaches the branch: SKILL-004 auto-fix did not rewrite line 7').toBe(POST_FIX_LINE_7);
  expect(existsSync(path.join(dir, '.hackmyagent-backup')), 'fixture no longer reaches the branch: no backup was created').toBe(true);
}

describe('#274 secure-openclaw --fix on a run whose only attempt was disproved', () => {
  it('counts the disproved attempt as an issue, not a fix, and still discloses the backup and the rollback command', () => {
    const dir = fixture();
    const r = run(dir);
    assertTreeWasRewritten(dir);
    expect(r.stdout, 'a CLI failure is not a measurement').not.toMatch(/at .*\.js:\d+:\d+/);

    const counts = r.stdout.split('\n').find((l) => l.startsWith('Checks: '));
    expect(counts, r.stdout).toBeDefined();
    expect(counts).toMatch(/\| 0 fixed \|/);
    expect(r.stdout).toContain('[SKILL-004]');
    expect(r.stdout).not.toContain('Auto-Remediation Applied');

    // Property 2 — the write is disclosed whatever the confirmed count.
    expect(r.stdout).toContain('Backup created:');
    expect(r.stdout).toMatch(/To rollback:.*rollback/);
    expect(r.status).toBe(1);
  }, 180_000);

  it('--json reports fixed: 0 while the finding itself still carries the attempt', () => {
    const dir = fixture();
    const r = run(dir, ['--json']);
    assertTreeWasRewritten(dir);
    const json = JSON.parse(r.stdout);
    const skill004 = (json.findings as Array<{ checkId: string; fixed?: boolean; fixVerified?: boolean }>)
      .find((f) => f.checkId === 'SKILL-004');
    expect(skill004, 'fixture no longer reaches the branch: SKILL-004 not in the findings').toBeDefined();
    expect(skill004!.fixed, 'fixture no longer reaches the branch: SKILL-004 was not attempted').toBe(true);
    expect(skill004!.fixVerified, 'fixture no longer reaches the branch: the attempt was not disproved').toBe(false);

    expect(json.fixed).toBe(0);
    expect(json.issues).toBeGreaterThanOrEqual(1);
    expect(r.status).toBe(1);
  }, 180_000);
});
