/**
 * #374 — `--fix` announced a score its own next scan disagreed with.
 *
 * Measured on the published artifacts, on a fixture of `package.json`, a
 * `.claude/settings.json` holding a `ghp_` token plus a `postgres://u:pw@host/db`
 * URL, and a `.mcp.json` with a token in `env`:
 *
 *     step                          0.25.1    0.25.2
 *     secure before                 64        64
 *     secure --fix announces        69        69
 *     secure rescan after           69        59   <- contradicts, below the start
 *     rescan, archive moved aside   69        69   <- exactly what --fix announced
 *
 * `backupContext` exists only inside a `--fix` run, so the config walk
 * (`scanner.ts:4741`) and Layer 2 (`:2122`) excluded the archive that run had
 * just created, while every later scan — which has no context — included it. Two
 * numbers from one run, describing two different trees.
 *
 * WHAT THIS IS NOT. It is not "the archive should be excluded from scoring".
 * Excluding by location hands a scanned tree a suppression token and reopens
 * #305/#309/#341; a pre-existing archive really does hold a plaintext secret and
 * is reported deliberately (`scanner.ts:4769`, restated at `:2117`). Measured on
 * the #298 fixture, on this build, the archive copies are reported by a plain
 * rescan with score 39 — identical to what `--fix` now announces. The inclusion
 * was never the outlier; the `--fix` run's exemption from it was.
 *
 * So the fix computes the announced score the way the next scan will, and the
 * report names the live-tree figure separately (`scoreExcludingOwnArchive`) so a
 * post-fix number that went DOWN is attributable rather than mysterious.
 *
 * Both directions are pinned here, because either alone is insufficient:
 *   1. the announced score equals the immediately-following rescan — and
 *      deliberately does NOT assert which value the two settle on, so the test
 *      cannot be satisfied by re-introducing an exclusion;
 *   2. a `.hackmyagent-backup` that is NOT this run's own is still scanned, still
 *      reported, and never flagged as ours — the #341 property that the first
 *      proposed fix for this issue (reusing `resolveArchiveBase`, a WRITE-gate
 *      predicate, as a scan-suppression predicate) would have broken.
 *
 * Credential values are synthesised at runtime, never written as literals, so
 * nothing here trips GitHub push protection or a secret scanner.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, readdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const FAKE_PG_URL = `postgres://svcuser:${'b'.repeat(12)}@db.internal:5432/appdb`;

/** The #374 fixture: a credential the fix redacts, in a tree it will archive. */
async function makeFixture(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  await mkdir(path.join(dir, '.claude'), { recursive: true });
  await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
  await writeFile(
    path.join(dir, '.claude', 'settings.json'),
    JSON.stringify({ githubToken: FAKE_GH_TOKEN, databaseUrl: FAKE_PG_URL }) + '\n',
  );
  await writeFile(
    path.join(dir, '.mcp.json'),
    JSON.stringify({
      mcpServers: { gh: { command: 'npx', args: ['-y', 'srv'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: FAKE_GH_TOKEN } } },
    }) + '\n',
  );
  return dir;
}

describe('#374 the score --fix announces is the score the next scan produces', () => {
  it('announced score equals the immediately-following rescan', async () => {
    const dir = await makeFixture('hma-374-agree-');
    try {
      const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      // A brand-new scanner with no `backupContext` — this is what the user's
      // next `secure` invocation is, and it is the authority on the number they
      // will see again.
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });

      // ── Non-vacuity, before the assertion that matters ──
      // An archive has to exist, or "the two numbers agree" is trivially true.
      const stamps = await readdir(path.join(dir, '.hackmyagent-backup')).catch(() => [] as string[]);
      expect(stamps.length, 'no archive was created, so this run never exercised the defect').toBeGreaterThan(0);
      // The archive has to have contributed a finding, or there is no divergence
      // for the two numbers to have disagreed about.
      expect(
        rescan.findings.filter((f) => (f.file ?? '').includes('.hackmyagent-backup')).length,
        'the rescan found nothing in the archive; the fixture no longer reproduces #374',
      ).toBeGreaterThan(0);
      // And there has to be real work in the tree at all.
      expect(before.score, 'the fixture scored clean; nothing is being measured').toBeLessThan(100);

      // ── The property ──
      // Deliberately NOT `toBe(59)` or any literal. Pinning the value would let
      // a future change satisfy this test by excluding the archive from BOTH
      // numbers, which is the retracted direction that reopens #305/#309/#341.
      // What must hold is only that one run cannot print two numbers for one
      // tree. Fails on the pre-fix build: 69 announced vs 59 rescanned.
      expect(
        fixed.score,
        `--fix announced ${fixed.score} and the immediately-following rescan said `
        + `${rescan.score}, with nothing changed in between: two numbers, two trees (#374)`,
      ).toBe(rescan.score);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('names the live-tree score, and it is the tree with the archive removed', async () => {
    const dir = await makeFixture('hma-374-live-');
    try {
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      const flagged = fixed.findings.filter((f) => f.inOwnArchive);
      expect(flagged.length, 'no finding was attributed to this run\'s own archive').toBeGreaterThan(0);
      // Every flagged finding must actually be in the archive. A flag applied by
      // name, or applied too widely, would advertise a live-tree credential as
      // recoverable-by-deleting-the-archive — the opposite of the truth.
      for (const f of flagged) {
        expect(f.file ?? '', `${f.checkId} is flagged as archived but sits at ${f.file}`)
          .toContain('.hackmyagent-backup');
      }

      // No archive-located finding may be left UNFLAGGED. `scoreExcludingOwnArchive`
      // is derived by dropping flagged findings, so an unflagged archive copy is
      // counted as live tree, and the report then tells the user those points do
      // not come back when the archive goes — the inverse of what the line says.
      // The adoption loop used to `continue` past any finding the main scan already
      // held, dropping the flag with it.
      //
      // NOTE ON WHAT THIS DOES AND DOES NOT PROVE: on the current tree the main
      // scan's Layer-2 walk excludes the archive, so no such finding arrives and
      // this passes on the pre-fix code too. It pins the invariant; it does not
      // red-proof the repair. The wiring it depends on — Layer 2 being handed
      // `isOwnBackupDir` — has no guard of its own (#382).
      const unflagged = fixed.findings.filter(
        (f) => (f.file ?? '').includes('.hackmyagent-backup') && !f.inOwnArchive,
      );
      expect(
        unflagged.map((f) => `${f.checkId} ${f.file}`),
        'an archive-located finding is not flagged, so the live-tree score counts it as live tree',
      ).toEqual([]);

      // The second number exists and is a real number, not a copy of the first.
      expect(fixed.scoreExcludingOwnArchive, 'the live-tree score was never computed').toBeDefined();
      // Dropping findings can only lower the weighted sum, so the live tree can
      // never score WORSE than the tree that also contains the archive.
      expect(fixed.scoreExcludingOwnArchive!).toBeGreaterThanOrEqual(fixed.score);

      // And it is the same number a scan of the tree WITHOUT the archive gets.
      // This is the claim the report makes to the user, verified end to end
      // rather than asserted from the arithmetic that produced it.
      const { rename } = await import('node:fs/promises');
      const aside = path.join(path.dirname(dir), `${path.basename(dir)}-aside`);
      await rename(path.join(dir, '.hackmyagent-backup'), aside);
      try {
        const withoutArchive = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        expect(
          fixed.scoreExcludingOwnArchive,
          `the report advertised a live tree of ${fixed.scoreExcludingOwnArchive} but a scan of `
          + `that same tree with the archive removed scores ${withoutArchive.score}`,
        ).toBe(withoutArchive.score);
      } finally {
        await rm(aside, { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('leaves the second number unset on a scan that created no archive', async () => {
    // `undefined` has to stay distinguishable from "equal to the score", or the
    // report prints a delta line for an archive that does not exist.
    const dir = await makeFixture('hma-374-detect-');
    try {
      const detectOnly = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      expect(detectOnly.score, 'the fixture scored clean; nothing is being measured').toBeLessThan(100);
      expect(detectOnly.scoreExcludingOwnArchive).toBeUndefined();
      expect(detectOnly.findings.some((f) => f.inOwnArchive)).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /**
   * Direction 3 — the same property at a NON-DEFAULT scan depth.
   *
   * The first fix for #374 built the verify scan's options from scratch, so it
   * inherited neither `scanDepth` nor `deep` and always ran at `standard`. Its
   * findings are adopted into the run's score, so `--fix --scan-depth quick`
   * announced a number carrying Layer-2 findings that `isQuick` (`scanner.ts:2138`)
   * means the user's next quick scan can never report. #374, through a second door.
   *
   * Asserts `rawScore` and not only `score`. Measured on the pre-fix build with
   * this fixture: announced rawScore 72, immediate quick rescan 85 — while the
   * DISPLAYED score was 69 both times, because the #259 clamp floored both to the
   * same value. A test that pinned only `score` would have passed on the broken
   * build and proved nothing.
   */
  it('announced score equals the next scan at the SAME depth the run used', async () => {
    // `.cursor/mcp.json` is doing specific work: it is in `BACKUP_FILES`, so a
    // `--fix` archives it, AND it is a Layer-2 surface, so only a standard-depth
    // scan reports the token in it. `.mcp.json` is NOT a backup candidate and
    // `secrets.json` is not a Layer-2 credential surface — neither reproduces this
    // alone. `secrets.json` is here world-readable so PERM-001, which quick depth
    // does detect, gives the quick run a fix to perform.
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-374-depth-'));
    try {
      await mkdir(path.join(dir, '.cursor'), { recursive: true });
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      await writeFile(path.join(dir, '.gitignore'), 'node_modules/\n');
      await writeFile(
        path.join(dir, '.cursor', 'mcp.json'),
        JSON.stringify({
          mcpServers: { gh: { command: 'npx', args: ['-y', 'srv'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: FAKE_GH_TOKEN } } },
        }) + '\n',
      );
      const secrets = path.join(dir, 'secrets.json');
      await writeFile(secrets, JSON.stringify({ note: 'no credential here' }) + '\n');
      await chmod(secrets, 0o644);

      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true, scanDepth: 'quick' });
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false, scanDepth: 'quick' });

      // ── Non-vacuity ──
      const stamps = await readdir(path.join(dir, '.hackmyagent-backup')).catch(() => [] as string[]);
      expect(stamps.length, 'no archive was created, so this run never exercised the defect').toBeGreaterThan(0);
      // The fixture only tests anything if it is genuinely depth-sensitive: the
      // archive must hold something STANDARD depth reports and QUICK does not.
      // Without this, a quick/quick agreement is trivially true and the test would
      // keep passing if the depth mismatch came back.
      const deeper = await new HardeningScanner().scan({ targetDir: dir, autoFix: false, scanDepth: 'standard' });
      const archived = (r: { findings: { file?: string; checkId?: string }[] }) =>
        r.findings.filter((f) => (f.file ?? '').includes('.hackmyagent-backup'));
      expect(
        archived(deeper).length,
        'standard depth reported nothing inside the archive; the fixture is no longer depth-sensitive '
        + 'and this test cannot detect the defect it exists for',
      ).toBeGreaterThan(archived(rescan).length);
      expect(fixed.rawScore, 'rawScore is unset, so the assertion below would compare undefined to undefined').toBeDefined();
      expect(rescan.rawScore).toBeDefined();

      // ── The property, on the unclamped number ──
      expect(
        fixed.rawScore,
        `--fix --scan-depth quick announced rawScore ${fixed.rawScore} and the immediately-following `
        + `quick rescan said ${rescan.rawScore}. The verify scan is not running at the depth the run used, `
        + `so the announced score counts findings the user's next scan cannot produce (#374)`,
      ).toBe(rescan.rawScore);
      expect(fixed.score, 'the displayed scores disagree as well').toBe(rescan.score);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /**
   * Direction 2. This must PASS on the pre-fix build as well — it is here so a
   * fix that over-excludes is caught, not to demonstrate a repair.
   */
  it('still scans a .hackmyagent-backup that is not this run\'s own, and never flags it as ours', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-374-foreign-'));
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      // Not at the scan root: the #341 case. `config.json` rather than an
      // arbitrary name so the config-shaped walk reliably reaches it.
      const foreign = path.join(dir, 'vendor', '.hackmyagent-backup', '2026-01-01-000000');
      await mkdir(foreign, { recursive: true });
      await writeFile(path.join(foreign, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
      // A live credential too, so the fix has something to archive and this run
      // therefore HAS an archive of its own to confuse the foreign one with.
      await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      const inForeign = result.findings.filter(
        (f) => (f.file ?? '').startsWith(`vendor${path.sep}.hackmyagent-backup`)
          || (f.file ?? '').startsWith('vendor/.hackmyagent-backup'),
      );
      expect(
        inForeign.length,
        'a .hackmyagent-backup below the scan root suppressed a real credential — '
        + 'the exclusion is a token the scanned tree can type (#305/#309/#341)',
      ).toBeGreaterThan(0);
      // The flag is about ownership, and this directory is not ours. Flagging it
      // would tell the user those points come back when they delete OUR archive.
      for (const f of inForeign) {
        expect(
          f.inOwnArchive ?? false,
          `${f.checkId} at ${f.file} was claimed as this run's own archive`,
        ).toBe(false);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
