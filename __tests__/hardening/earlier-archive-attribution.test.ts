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
 * #376 — `--fix` writes its backup to the store outside the tree, so a second
 * run by this version leaves nothing behind for the third to explain, and
 * `scoreExcludingOwnArchive` and `inOwnArchive` are gone. The state above still
 * exists in every tree 0.25.x to 0.33.x fixed: the plaintext copy sits in
 * `.hackmyagent-backup`, the live file is redacted, and the next run has to
 * attribute what it finds there. The fixture builds that state from a real
 * `--fix` run, moved to the layout those versions wrote.
 *
 * Credential values are synthesised at runtime, never written as literals.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { latestStoreRun, storeDirOf } from '../helpers/backup-store';

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

/**
 * `--fix` as an earlier version left the tree: the live file redacted, and the
 * run's copies in `<target>/.hackmyagent-backup/<stamp>/`, with no run in the
 * store. Returns the stamp.
 */
async function fixAsEarlierVersion(dir: string): Promise<string> {
  await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
  const run = await latestStoreRun(dir);
  const stamp = path.basename(run);
  await mkdir(path.join(dir, '.hackmyagent-backup'), { recursive: true });
  await cp(run, path.join(dir, '.hackmyagent-backup', stamp), { recursive: true });
  await rm(await storeDirOf(dir), { recursive: true, force: true });
  return stamp;
}

function runCli(args: string[], home: string): string {
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

/**
 * The Next Steps section of a rendered report: up to the `Backups:` line when
 * the run prints one, else up to the version footer. The `Backups:` line (#376)
 * follows the section and is not a step; it names the "--fix backup" the store
 * holds, which is not a citation of `secure --fix`.
 */
function nextSteps(out: string): string {
  const at = out.indexOf('Next Steps');
  expect(at, 'the report printed no Next Steps section').toBeGreaterThan(-1);
  const ends = [out.indexOf('\nBackups:', at), out.indexOf('Scanned with', at)].filter((i) => i !== -1);
  return out.slice(at, ends.length ? Math.min(...ends) : undefined);
}

describe('#383 findings inside an earlier run\'s backup are attributed, not exempted', () => {
  it('a second --fix run flags the first run\'s archive findings and leaves the score alone', async () => {
    const dir = await makeFixture('hma-383-second-fix-');
    try {
      const stamp = await fixAsEarlierVersion(dir);
      const second = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });

      // ── Non-vacuity: the earlier run's archive is in the tree, and it is the
      // only one there. The second run added none (#376).
      expect(
        await readdir(path.join(dir, '.hackmyagent-backup')),
        'the second --fix run wrote a backup into the tree',
      ).toEqual([stamp]);
      const archived = second.findings.filter((f) => inBackupBase(f.file));
      expect(archived.length, 'the first run\'s plaintext copy was not reported').toBeGreaterThan(0);

      // ── The property ──
      for (const f of archived) {
        expect(f.inArchive, `${f.checkId} at ${f.file} is inside the archive base but unflagged`).toBe(true);
      }
      // #376 — nothing claims a copy as this run's own, and no result carries a
      // second number. Both fields are removed, not left unset: a field that is
      // present implies a measurement that is no longer made.
      expect('scoreExcludingOwnArchive' in second, 'the retired second score is back on the result').toBe(false);
      for (const f of second.findings) {
        expect('inOwnArchive' in f, `${f.checkId} at ${f.file} carries the retired own-archive flag`).toBe(false);
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
      await fixAsEarlierVersion(dir);
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      const out = runCli(['secure', dir], home);
      expect(out, 'the earlier backup findings went unexplained next to the score').toMatch(
        /findings? above sits? inside \.hackmyagent-backup, where earlier versions of HackMyAgent kept this tree's --fix backups\. (It|They) counts? toward this score\./,
      );
      expect(out).toContain('never edit a backup');
      // The store holds the second run's backup, so this report also prints
      // the `Backups:` line, after the section measured here.
      expect(out).toMatch(/\nBackups: 1 --fix backup of this directory/);
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
