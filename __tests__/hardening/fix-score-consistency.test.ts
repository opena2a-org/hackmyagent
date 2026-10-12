/**
 * #374 / #376 — the score `--fix` announces is the score of the live tree, and
 * it is what every later scan produces.
 *
 * #374 measured the contradiction on the published artifacts, on a fixture of
 * `package.json`, a `.claude/settings.json` holding a `ghp_` token plus a
 * `postgres://` URL with a user and password, and a `.mcp.json` with a token in `env`:
 *
 *     step                          0.25.1    0.25.2
 *     secure before                 64        64
 *     secure --fix announces        69        69
 *     secure rescan after           69        59   <- contradicts, below the start
 *     rescan, archive moved aside   69        69   <- exactly what --fix announced
 *
 * The archive `--fix` wrote sat INSIDE the scanned tree, so every later scan
 * reported its copies. #374 reconciled the two numbers by counting the archive
 * in the announced score too, and printed the live-tree figure beside it
 * (`scoreExcludingOwnArchive`). That made the numbers agree on the lower one.
 *
 * #376 removed the cause: the archive is in the per-user backup store, outside
 * the tree, so no scan reaches it. The announced score, the rescan and the
 * score of the tree with no archive anywhere are one number, and there is no
 * second number to print. Measured on the #298 fixture: 35 announced and 35 on
 * every rescan before, 59 for all three after.
 *
 * WHAT THIS IS NOT. It is not "the archive is excluded from scoring". Nothing
 * is skipped by name or location: a `.hackmyagent-backup` an earlier version
 * wrote into a tree, or one a tree ships, is still scanned and reported (the
 * last two cases). The run's copies simply are not in the tree any more.
 *
 * Credential values are synthesised at runtime, never written as literals, so
 * nothing here trips GitHub push protection or a secret scanner.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, readFile, chmod } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { latestStoreRun, storeDirOf } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const FAKE_PG_URL = `postgres://svcuser:${'b'.repeat(12)}@db.internal:5432/appdb`;

/** A `ghp_` value no vendor issued: 36 random alphanumerics, generated per run. */
function randomGhToken(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return `ghp_${[...randomBytes(36)].map((b) => alphabet[b % alphabet.length]).join('')}`;
}

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

const inTreeArchive = (r: { findings: { file?: string }[] }) =>
  r.findings.filter((f) => (f.file ?? '').toLowerCase().includes('.hackmyagent-backup'));

describe('#374/#376 the score --fix announces is the score the next scan produces', () => {
  it('announced score equals the rescan and the score of the tree with no archive anywhere', async () => {
    const dir = await makeFixture('hma-374-agree-');
    try {
      const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      // A brand-new scanner with no `backupContext` — this is what the user's
      // next `secure` invocation is, and it is the authority on the number they
      // will see again.
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });

      // ── Non-vacuity, before the assertion that matters ──
      // There is real work in the tree, and the run archived a plaintext copy of
      // the credential it redacted: the copy that, inside the tree, every later
      // scan reported.
      expect(before.score, 'the fixture scored clean; nothing is being measured').toBeLessThan(100);
      expect(
        await readFile(path.join(await latestStoreRun(dir), '.claude', 'settings.json'), 'utf-8'),
        'the run archived no plaintext copy, so there was nothing a later scan could have charged',
      ).toContain(FAKE_GH_TOKEN);

      // ── The property ──
      // Deliberately NOT a literal: what must hold is that one run cannot print
      // two numbers for one tree, and that the number is the live tree's.
      expect(
        fixed.score,
        `--fix announced ${fixed.score} and the immediately-following rescan said `
        + `${rescan.score}, with nothing changed in between: two numbers, two trees (#374)`,
      ).toBe(rescan.score);
      expect(fixed.rawScore).toBe(rescan.rawScore);
      expect(inTreeArchive(rescan), 'a later scan found a backup copy inside the tree (#376)').toEqual([]);

      // And the backup store is not part of the measurement at all: deleting it
      // changes nothing a scan reports.
      await rm(await storeDirOf(dir), { recursive: true, force: true });
      const withoutArchive = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      expect(withoutArchive.score).toBe(fixed.score);
      expect(withoutArchive.rawScore).toBe(fixed.rawScore);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('carries no second score on a fixing run or a detect-only one', async () => {
    // #374's `scoreExcludingOwnArchive` described the tree with this run's
    // archive removed. With the archive outside the tree that is the score
    // itself, so a second field could only imply a measurement nobody made.
    const dir = await makeFixture('hma-376-one-');
    try {
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const detect = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      expect(fixed.backupPath, 'the run made no backup, so this measures nothing').toBeDefined();
      for (const r of [fixed, detect]) {
        expect(Object.keys(r)).not.toContain('scoreExcludingOwnArchive');
        expect(r.findings.some((f) => 'inOwnArchive' in f)).toBe(false);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /**
   * Direction 3 — the same property at a NON-DEFAULT scan depth.
   *
   * The first fix for #374 built the verify scan's options from scratch, so it
   * inherited neither `scanDepth` nor `deep` and always ran at `standard`, and
   * `--fix --scan-depth quick` announced a number carrying Layer-2 findings the
   * user's next quick scan can never report. The verify scan no longer feeds
   * the score (#376), and the property is pinned anyway: a quick `--fix`
   * announces what a quick rescan says.
   *
   * Asserts `rawScore` and not only `score`: the #259 clamp can floor two
   * different raw scores to one displayed value.
   */
  it('announced score equals the next scan at the SAME depth the run used', async () => {
    // `.cursor/mcp.json` is in `BACKUP_FILES` and is a Layer-2 surface, so the
    // backup holds a copy only a standard-depth scan would report. `secrets.json`
    // is world-readable so PERM-001, which quick depth does detect, gives the
    // quick run a fix to perform.
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
      expect(fixed.findings.some((f) => f.fixed), 'the quick run fixed nothing; nothing is being measured').toBe(true);
      expect(
        await readFile(path.join(await latestStoreRun(dir), '.cursor', 'mcp.json'), 'utf-8'),
        'the backup holds no copy of the Layer-2 surface',
      ).toContain(FAKE_GH_TOKEN);
      expect(fixed.rawScore, 'rawScore is unset, so the assertion below would compare undefined to undefined').toBeDefined();
      expect(rescan.rawScore).toBeDefined();

      // ── The property, on the unclamped number ──
      expect(
        fixed.rawScore,
        `--fix --scan-depth quick announced rawScore ${fixed.rawScore} and the immediately-following `
        + `quick rescan said ${rescan.rawScore}`,
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

  /**
   * #376 — an archive an earlier version wrote INTO the tree, in the layout it
   * used (`<target>/.hackmyagent-backup/<stamp>/`), is not exempted by the move.
   * It holds a plaintext credential, so it is reported CRITICAL like any other
   * copy, on a detect-only scan and on a `--fix` run alike, until the user
   * deletes it. No predicate skips it by name or by path.
   */
  it('reports a legacy in-tree archive\'s plaintext credential as CRITICAL', async () => {
    const dir = tempDir('hma-376-legacy-');
    await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
    const legacy = path.join(dir, '.hackmyagent-backup', '2026-08-01-120000000-000-0a1b2c3d');
    await mkdir(legacy, { recursive: true });
    await writeFile(
      path.join(legacy, '.manifest.json'),
      JSON.stringify({ version: 2, existingFiles: ['config.json'], absentAtBackup: [], createdFiles: [] }),
    );
    await writeFile(path.join(legacy, 'config.json'), JSON.stringify({ githubToken: randomGhToken() }, null, 2) + '\n');
    const archived = path.join('.hackmyagent-backup', path.basename(legacy), 'config.json');

    for (const autoFix of [false, true]) {
      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix });
      const hit = result.findings.find((f) => f.checkId === 'CRED-001' && f.file === archived);
      expect(hit, `autoFix=${autoFix}: the legacy archive's credential was not reported`).toBeDefined();
      expect(hit!.severity).toBe('critical');
      expect(hit!.passed).toBe(false);
      expect(hit!.inArchive, 'the legacy archive is not attributed as one').toBe(true);
    }
  });
});
