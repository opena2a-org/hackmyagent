/**
 * #383 — a second `secure --fix` reported a low score with no explanation.
 *
 * #374 made `--fix` attribute a score depressed by the archive it had just
 * written ("Live tree: 100/100 — the 31-point difference is 2 findings inside
 * the backup this run created"). Run `--fix` again on the same tree and that
 * line disappeared while the score stayed down: the second run's own archive
 * holds only redacted copies, so nothing in it is a finding and
 * `scoreExcludingOwnArchive` is unset, while the plaintext sits in the FIRST
 * run's archive. The report then pointed at `secure --fix`, `fix-all` and
 * `protect`, none of which edits a backup.
 *
 * The fix attributes, it does not exempt. Every finding inside the target's
 * archive base carries `inArchive`; the score, the verdict and the findings are
 * unchanged, and no second number is derived from a copy whose author cannot be
 * proven. Pinned here:
 *   1. the second run's archive findings carry `inArchive`, are not claimed as
 *      this run's own, and the score equals the plain rescan's (the #374
 *      property still holds with the flag present);
 *   2. a directory merely NAMED `.hackmyagent-backup` elsewhere in the tree is
 *      still reported and never flagged (#305/#309/#341);
 *   3. the rendered report explains those findings next to the score and its
 *      Next Steps stop citing commands that cannot move them — while a live
 *      credential still gets them.
 *
 * Credential values are synthesised at runtime, never written as literals.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/**
 * One credential in one config file and nothing else, so after `--fix` the
 * archived copies are the ONLY findings. (A `package.json` would add a live
 * DEP-001 that `secure --fix` really can address, and the Next Steps check
 * below would be measuring that instead.)
 */
async function makeFixture(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
  return dir;
}

const inBackupBase = (file: string | undefined): boolean =>
  (file ?? '').split(/[\\/]/)[0] === '.hackmyagent-backup';

function runCli(args: string[], home: string): string {
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

/** The Next Steps section of a rendered report, up to the version footer. */
function nextSteps(out: string): string {
  const at = out.indexOf('Next Steps');
  expect(at, 'the report printed no Next Steps section').toBeGreaterThan(-1);
  const end = out.indexOf('Scanned with', at);
  return out.slice(at, end === -1 ? undefined : end);
}

describe('#383 findings inside an earlier run\'s backup are attributed, not exempted', () => {
  it('a second --fix run flags the first run\'s archive findings and leaves the score alone', async () => {
    const dir = await makeFixture('hma-383-second-fix-');
    try {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const second = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });

      // ── Non-vacuity: this is the #383 state, not the #374 one ──
      const stamps = await readdir(path.join(dir, '.hackmyagent-backup'));
      expect(stamps.length, 'two --fix runs should have left two archives').toBeGreaterThanOrEqual(2);
      expect(
        second.scoreExcludingOwnArchive,
        'the second run attributed its own archive, so the #374 line would print and this is not #383',
      ).toBeUndefined();
      const archived = second.findings.filter((f) => inBackupBase(f.file));
      expect(archived.length, 'the first run\'s plaintext copy was not reported').toBeGreaterThan(0);

      // ── The property ──
      for (const f of archived) {
        expect(f.inArchive, `${f.checkId} at ${f.file} is inside the archive base but unflagged`).toBe(true);
        expect(f.inOwnArchive ?? false, `${f.checkId} at ${f.file} was claimed as this run's own`).toBe(false);
      }
      for (const f of second.findings.filter((x) => !inBackupBase(x.file))) {
        expect(f.inArchive ?? false, `${f.checkId} at ${f.file} is outside the archive but flagged`).toBe(false);
      }
      // A detect-only scan attributes the same copies.
      expect(rescan.findings.filter((f) => f.inArchive).length).toBe(archived.length);
      // Attribution only: the number is the one the next scan produces (#374).
      expect(second.score).toBe(rescan.score);
      expect(second.score, 'the archived plaintext stopped counting against the score').toBeLessThan(100);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 240_000);

  it('never flags a directory merely named .hackmyagent-backup below the scan root', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-383-lookalike-'));
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      const lookalike = path.join(dir, 'vendor', '.hackmyagent-backup', '2026-01-01-000000');
      await mkdir(lookalike, { recursive: true });
      await writeFile(path.join(lookalike, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const inLookalike = result.findings.filter((f) => (f.file ?? '').split(/[\\/]/)[0] === 'vendor');
      expect(inLookalike.length, 'a nested .hackmyagent-backup suppressed a real credential').toBeGreaterThan(0);
      for (const f of inLookalike) {
        expect(f.inArchive ?? false, `${f.checkId} at ${f.file} was attributed to the archive base`).toBe(false);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 120_000);

  it('the report explains the earlier backup and stops citing commands that cannot move it', async () => {
    // The only case here that reads the built CLI. Without a build it fails
    // by name, with the command to run; the library cases above do not wait.
    assertDistFresh();
    const dir = await makeFixture('hma-383-render-');
    const home = await mkdtemp(path.join(tmpdir(), 'hma-383-home-'));
    const control = await makeFixture('hma-383-control-');
    try {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      const out = runCli(['secure', dir], home);
      expect(out, 'the earlier backup findings went unexplained next to the score').toMatch(
        /findings? above sits? inside \.hackmyagent-backup, where HackMyAgent keeps this tree's --fix backups, in a copy this run did not create\. (It|They) counts? toward this score\./,
      );
      expect(out).toContain('never edit a backup');
      const steps = nextSteps(out);
      expect(steps, 'Next Steps cited secure --fix for findings it never edits').not.toContain('--fix');
      expect(steps, 'Next Steps cited protect for findings it never edits').not.toContain('protect');

      // Control: a live credential with no archive keeps both commands and gets
      // no backup explanation.
      const live = runCli(['secure', control], home);
      expect(live).not.toContain('inside .hackmyagent-backup');
      const liveSteps = nextSteps(live);
      expect(liveSteps).toContain('--fix');
      expect(liveSteps).toContain('protect');
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
      await rm(control, { recursive: true, force: true });
    }
  }, 480_000);
});
