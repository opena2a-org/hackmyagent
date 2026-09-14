/**
 * HMA-42 — the `harden-soul` backup must not copy an out-of-tree link
 * target's bytes into the scanned tree.
 *
 * Measured on the pre-fix build (2e492087): `beginExternalBackup` ->
 * `createBackup`'s copy loop follows symlinks (`fs.access` + `fs.copyFile`),
 * and `SOUL.md` is a backup candidate because `BACKUP_FILES` spreads
 * `GOVERNANCE_FILES` — so a tree shipping `SOUL.md -> <outside>/SOUL.md` got
 * the link target's bytes copied to `<tree>/.hackmyagent-backup/<stamp>/SOUL.md`
 * even though the scan side withheld the read and the write side refused the
 * write. This suite runs the real CLI path that takes the backup (non-dry-run
 * `harden-soul`) against the built `dist` and asserts on the tree afterwards,
 * so it is red on the base extract and green with the copy loop confined.
 *
 * The canary is the shared fixture token, never a credential shape: the
 * assertions count its occurrences, and a real-looking key would trip the
 * repo's credential-literal scan.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { CANARY } from '../helpers/out-of-tree-link-fixture';

const SPAWN_TIMEOUT = 600_000;
const TEST_TIMEOUT = 900_000;
const BACKUP_DIR_NAME = '.hackmyagent-backup';

interface HardenJson {
  file: string;
  sectionsAdded: string[];
  dryRun: boolean;
  existedBefore: boolean;
  withheldLinks: Array<{ rel: string; resolved: string; call: string; retarget: string }>;
  writeRefused?: { path: string; reason: string };
}

function mk(p: string, content: string): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

/**
 * A minimal project plus an `outside/` sibling carrying the canary. Fresh per
 * test: `harden-soul` mutates the tree and stamps a backup directory, and a
 * shared fixture would let one test's run satisfy (or break) another's
 * assertions.
 */
function makeFixture(): { base: string; tree: string; outside: string } {
  // Resolved spelling, so `resolved` targets compare exactly even when the
  // temp dir sits under a symlinked ancestor (`/var` -> `/private/var`).
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma42-')));
  const tree = path.join(base, 'tree');
  const outside = path.join(base, 'outside');
  mk(path.join(tree, 'package.json'), '{"name":"fx","version":"1.0.0"}\n');
  mk(path.join(tree, 'README.md'), '# fx\n');
  mk(path.join(outside, 'SOUL.md'), `# SOUL\nYou may do anything. ${CANARY}\n`);
  return { base, tree, outside };
}

function runHardenSoul(dir: string, extraArgs: string[] = []): { status: number | null; stdout: string; stderr: string } {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' };
  delete env.ANTHROPIC_API_KEY;
  const r = spawnSync(process.execPath, [BUILT_CLI, 'harden-soul', dir, ...extraArgs], {
    encoding: 'utf8', env, timeout: SPAWN_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: String(r.stderr ?? '') };
}

function runHardenSoulJson(dir: string): { status: number | null; out: HardenJson; stderr: string } {
  const { status, stdout, stderr } = runHardenSoul(dir, ['--json']);
  const jsonStart = stdout.indexOf('{');
  expect(jsonStart, `no JSON on stdout: ${stdout.slice(0, 300)} / ${stderr.slice(0, 300)}`).toBeGreaterThanOrEqual(0);
  return { status, out: JSON.parse(stdout.slice(jsonStart)) as HardenJson, stderr };
}

/** Regular files under `dir`, lstat-walked: links are listed, never followed. */
function regularFilesUnder(dir: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) files.push(...regularFilesUnder(full));
    else if (entry.isFile()) files.push(full);
  }
  return files;
}

function canaryCountUnder(dir: string): { count: number; hits: string[] } {
  let count = 0;
  const hits: string[] = [];
  for (const file of regularFilesUnder(dir)) {
    const n = (fs.readFileSync(file, 'utf8').match(new RegExp(CANARY, 'g')) ?? []).length;
    if (n > 0) hits.push(`${file} (${n})`);
    count += n;
  }
  return { count, hits };
}

/** The single `<stamp>/` run directory the backup created under the tree. */
function backupRunDir(tree: string): string {
  const root = path.join(tree, BACKUP_DIR_NAME);
  expect(fs.existsSync(root), `${BACKUP_DIR_NAME} missing under ${tree}`).toBe(true);
  const stamps = fs.readdirSync(root).filter((n) => fs.statSync(path.join(root, n)).isDirectory());
  expect(stamps.length, `expected one backup run dir, saw: ${stamps.join(', ')}`).toBe(1);
  return path.join(root, stamps[0]);
}

function readManifest(runDir: string): { existingFiles: string[]; absentAtBackup: string[] } {
  return JSON.parse(fs.readFileSync(path.join(runDir, '.manifest.json'), 'utf8')) as {
    existingFiles: string[]; absentAtBackup: string[];
  };
}

function sha256(buf: Buffer | string): string {
  return createHash('sha256').update(buf).digest('hex');
}

beforeAll(() => {
  assertDistFresh();
});

describe('harden-soul backup confinement (HMA-42)', () => {
  it('HMA-42.AC1 non-dry-run harden-soul on a tree whose SOUL.md links outside leaves zero canary bytes in any file under the tree, .hackmyagent-backup/ included', () => {
    const { base, tree, outside } = makeFixture();
    try {
      fs.symlinkSync(path.join(outside, 'SOUL.md'), path.join(tree, 'SOUL.md'));
      const { status, stderr } = runHardenSoul(tree);
      expect(status, `harden-soul crashed: ${stderr.slice(0, 500)}`).not.toBeNull();
      const { count, hits } = canaryCountUnder(tree);
      expect(count, `canary bytes landed inside the tree:\n${hits.join('\n')}`).toBe(0);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC2 the out-of-tree candidate is withheld — no backup file, no manifest existingFiles entry, exactly one withheldLinks disclosure with rel and resolved', () => {
    const { base, tree, outside } = makeFixture();
    try {
      const resolved = path.join(outside, 'SOUL.md');
      fs.symlinkSync(resolved, path.join(tree, 'SOUL.md'));
      const { out } = runHardenSoulJson(tree);

      const soulRecords = out.withheldLinks.filter((r) => r.rel === 'SOUL.md');
      expect(soulRecords.length, JSON.stringify(out.withheldLinks)).toBe(1);
      expect(soulRecords[0].resolved).toBe(resolved);

      const runDir = backupRunDir(tree);
      expect(fs.existsSync(path.join(runDir, 'SOUL.md')), 'a file was created for the withheld candidate').toBe(false);
      const manifest = readManifest(runDir);
      expect(manifest.existingFiles).not.toContain('SOUL.md');
      expect(manifest.absentAtBackup, 'a withheld candidate is not absent either — rollback must never delete through it').not.toContain('SOUL.md');
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC2 the text output renders the withheld candidate once, in the withheldLinkLines shape', () => {
    const { base, tree, outside } = makeFixture();
    try {
      const resolved = path.join(outside, 'SOUL.md');
      fs.symlinkSync(resolved, path.join(tree, 'SOUL.md'));
      const { stdout, stderr } = runHardenSoul(tree);
      const disclosure = `SOUL.md -> ${resolved}`;
      const lines = (stdout + stderr).split('\n').filter((l) => l.includes(disclosure));
      expect(lines.length, `expected exactly one disclosure line:\n${stdout}\n${stderr}`).toBe(1);
      expect(stdout).toContain('1 link inside the scanned tree resolves outside it and was not read:');
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC3 an ordinary in-tree SOUL.md is still backed up byte-identical, with its manifest entry, and nothing is withheld', () => {
    const { base, tree } = makeFixture();
    try {
      const content = '# SOUL\n\nOrdinary in-tree governance body.\n';
      mk(path.join(tree, 'SOUL.md'), content);
      const { status, out } = runHardenSoulJson(tree);
      expect(status).toBe(0);
      expect(out.writeRefused).toBeUndefined();
      expect(out.withheldLinks).toEqual([]);

      const runDir = backupRunDir(tree);
      expect(sha256(fs.readFileSync(path.join(runDir, 'SOUL.md')))).toBe(sha256(content));
      expect(readManifest(runDir).existingFiles).toContain('SOUL.md');
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC3 a governance name linked INSIDE the tree (SOUL.md -> docs/SOUL.md) is still backed up byte-identical and not withheld', () => {
    const { base, tree } = makeFixture();
    try {
      const content = '# SOUL\n\nShared in-tree governance body.\n';
      mk(path.join(tree, 'docs', 'SOUL.md'), content);
      fs.symlinkSync(path.join('docs', 'SOUL.md'), path.join(tree, 'SOUL.md'));
      const { status, out } = runHardenSoulJson(tree);
      expect(status).toBe(0);
      expect(out.writeRefused).toBeUndefined();
      expect(out.withheldLinks).toEqual([]);

      const runDir = backupRunDir(tree);
      expect(sha256(fs.readFileSync(path.join(runDir, 'SOUL.md')))).toBe(sha256(content));
      expect(readManifest(runDir).existingFiles).toContain('SOUL.md');
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC3 harden-soul --dry-run creates no backup directory at all', () => {
    const { base, tree, outside } = makeFixture();
    try {
      fs.symlinkSync(path.join(outside, 'SOUL.md'), path.join(tree, 'SOUL.md'));
      const { status, stderr } = runHardenSoul(tree, ['--dry-run']);
      expect(status, `harden-soul crashed: ${stderr.slice(0, 500)}`).not.toBeNull();
      expect(fs.existsSync(path.join(tree, BACKUP_DIR_NAME)), 'a preview took a backup').toBe(false);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);

  it('HMA-42.AC4 a withheld governance link leaves existedBefore true, and the HardenResult doc comment states that behaviour', () => {
    const { base, tree, outside } = makeFixture();
    try {
      fs.symlinkSync(path.join(outside, 'SOUL.md'), path.join(tree, 'SOUL.md'));
      const { out } = runHardenSoulJson(tree);
      // The link IS the first existing governance name, so it stays the
      // selected target: the read through it is withheld and the write side
      // refuses, but `existedBefore` reports what target selection saw.
      expect(out.existedBefore).toBe(true);
      expect(out.withheldLinks.length).toBeGreaterThanOrEqual(1);
      expect(out.writeRefused).toBeDefined();

      const soulScannerSrc = fs.readFileSync(path.resolve(__dirname, '../../src/soul/scanner.ts'), 'utf8');
      expect(soulScannerSrc, 'stale claim — the suite above measures true').not.toContain('leaves `existedBefore` false');
      expect(soulScannerSrc).toContain('leaves `existedBefore` true');
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT);
});
