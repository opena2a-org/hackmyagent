/**
 * #1039 — a `--fix` run keeps a copy only of what a fix changed.
 *
 * Measured on the #376 head this replaces: `createBackup` copied every backup
 * candidate that existed before any check ran, so a project whose `.env` was
 * `0600` and untouched by every fix still had a plaintext `.env` in the run
 * directory, and a `0644` `.env` whose only change was the permissions fix had
 * its whole content copied to restore one mode.
 *
 * Now a file is copied when a fix is about to write it (`ensureBackupCovers`),
 * and the permissions fix records a mode-only entry (`modeOnlyFiles`) before its
 * `chmod`. The census at the end ties every write and `chmod` of the target on
 * the `secure --fix` and `harden-soul` paths to one of those two records, both
 * statically (each mutation site is pinned to the gate in front of it) and at
 * run time (each call is judged against the run's manifest as it is made).
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { SoulScanner } from '../../src/soul/scanner';
import { fs as trackedFs } from '../../src/hardening/tracked-fs';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun, storeDirOf, storeRuns } from '../helpers/backup-store';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'c'.repeat(36)}`;

const tokenConfig = `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`;
/** No credential and nothing any check rewrites: only its mode can draw a fix. */
const plainEnv = 'PORT=8080\nLOG_LEVEL=info\n';

const mode = (p: string): number => statSync(p).mode & 0o7777;
const octal = (m: number): string => m.toString(8);

function put(dir: string, rel: string, content: string, fileMode: number): void {
  const p = path.join(dir, rel);
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, content);
  chmodSync(p, fileMode);
}

interface Manifest {
  version?: number;
  existingFiles: string[];
  existingFileModes?: Record<string, number>;
  modeOnlyFiles?: Record<string, number>;
  absentAtBackup: string[];
  absentAtFixWrite?: string[];
  createdFiles: Array<{ path: string; sha256: string }>;
}

const readManifest = (run: string): Manifest =>
  JSON.parse(readFileSync(path.join(run, '.manifest.json'), 'utf-8')) as Manifest;

/** Every file the run directory holds besides its manifest, run-relative. */
function filesIn(run: string, rel = ''): string[] {
  const out: string[] = [];
  for (const e of readdirSync(path.join(run, rel), { withFileTypes: true })) {
    const r = rel ? path.join(rel, e.name) : e.name;
    if (e.isDirectory()) out.push(...filesIn(run, r));
    else if (r !== '.manifest.json') out.push(r);
  }
  return out.sort();
}

async function fix(dir: string): Promise<string> {
  await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
  return latestStoreRun(dir);
}

const SKIP_MODES = process.platform === 'win32';

describe.skipIf(SKIP_MODES)('#1039 the run holds a copy only of what a fix changed', () => {
  it('keeps no .env when .env is 0600 and no fix touches it', async () => {
    const dir = tempDir('hma-1039-untouched-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, '.env', plainEnv, 0o600);

    const run = await fix(dir);

    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8'), 'the fix did not redact the credential; this cell measures nothing')
      .not.toContain(FAKE_GH_TOKEN);
    expect(readFileSync(path.join(dir, '.env'), 'utf-8')).toBe(plainEnv);
    expect(octal(mode(path.join(dir, '.env')))).toBe('600');

    const manifest = readManifest(run);
    expect(existsSync(path.join(run, '.env')), 'the run holds a copy of a .env no fix touched').toBe(false);
    expect(manifest.existingFiles).not.toContain('.env');
    expect(manifest.modeOnlyFiles?.['.env']).toBeUndefined();
    expect(manifest.existingFileModes?.['.env']).toBeUndefined();
    // Nor of anything else no fix wrote. config.json is the one file changed.
    expect(filesIn(run)).toEqual(['config.json']);
    expect(manifest.existingFiles).toEqual(['config.json']);
    expect(readFileSync(path.join(run, 'config.json'), 'utf-8')).toBe(tokenConfig);
  }, 120_000);

  it('records a mode-only entry for a 0644 .env whose content no fix changes, and rollback returns it to 0644', async () => {
    const dir = tempDir('hma-1039-mode-only-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, '.env', plainEnv, 0o644);

    const run = await fix(dir);

    expect(octal(mode(path.join(dir, '.env'))), 'the permissions fix did not narrow .env; this cell measures nothing').toBe('600');
    expect(readFileSync(path.join(dir, '.env'), 'utf-8'), 'a fix changed the content of .env; this cell measures nothing').toBe(plainEnv);

    const manifest = readManifest(run);
    expect(manifest.modeOnlyFiles?.['.env'], 'no mode-only entry was recorded before the chmod').toBe(0o644);
    expect(manifest.existingFiles).not.toContain('.env');
    expect(existsSync(path.join(run, '.env')), 'the run holds the content of a .env only its mode changed').toBe(false);
    expect(filesIn(run)).toEqual([]);

    const report = await new HardeningScanner().rollback(dir);

    expect(report.backupSource).toBe('store');
    expect(report.modesRestored).toEqual([{ path: '.env', mode: 0o644 }]);
    expect(report.restored).toEqual([]);
    expect(report.unrestored).toEqual([]);
    expect(octal(mode(path.join(dir, '.env'))), 'rollback did not undo the permissions fix').toBe('644');
    expect(readFileSync(path.join(dir, '.env'), 'utf-8')).toBe(plainEnv);
    expect(await storeRuns(dir), 'the run was not consumed').toEqual([]);
  }, 120_000);

  it('restores the bytes and the mode of every file a fix changed', async () => {
    const dir = tempDir('hma-1039-changed-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o640);
    put(dir, 'public/tool.py', 'print("ok")\n', 0o755);
    put(dir, '.env', plainEnv, 0o644);

    const run = await fix(dir);
    const manifest = readManifest(run);
    expect(manifest.existingFiles).toEqual(['config.json']);
    expect(manifest.existingFileModes).toEqual({ 'config.json': 0o640 });
    expect(manifest.modeOnlyFiles).toEqual({ '.env': 0o644 });
    expect(octal(mode(path.join(run, 'config.json'))), 'a copy in the store is readable by others').toBe('600');

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored).toEqual(['config.json']);
    expect(report.modesRestored).toEqual([{ path: '.env', mode: 0o644 }]);
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(tokenConfig);
    expect(octal(mode(path.join(dir, 'config.json')))).toBe('640');
    expect(octal(mode(path.join(dir, '.env')))).toBe('644');
    expect(octal(mode(path.join(dir, 'public/tool.py'))), 'a file no fix touched changed mode').toBe('755');
  }, 120_000);

  it('keeps the mode a file had before the chmod when a fix rewrites it afterwards', async () => {
    const dir = tempDir('hma-1039-chmod-then-write-');
    put(dir, '.env', plainEnv, 0o644);
    const scanner = new HardeningScanner();
    expect(await scanner.beginExternalBackup(dir), 'no backup could be taken').not.toBeNull();
    // The permissions fix's gate, then its chmod, then a later write to the same file.
    const gate = (scanner as unknown as { ensureModeRecorded(p: string): Promise<boolean> }).ensureModeRecorded.bind(scanner);
    expect(await gate(path.join(dir, '.env'))).toBe(true);
    chmodSync(path.join(dir, '.env'), 0o600);
    expect(await scanner.ensureGovernanceBackup(dir, '.env')).toBe(true);
    writeFileSync(path.join(dir, '.env'), 'PORT=9090\n');

    const run = await latestStoreRun(dir);
    const manifest = readManifest(run);
    expect(manifest.existingFiles).toEqual(['.env']);
    expect(manifest.existingFileModes, 'the copy recorded the mode the chmod left, not the one before it').toEqual({ '.env': 0o644 });
    expect(manifest.modeOnlyFiles ?? {}).toEqual({});

    const report = await new HardeningScanner().rollback(dir);
    expect(report.restored).toEqual(['.env']);
    expect(readFileSync(path.join(dir, '.env'), 'utf-8')).toBe(plainEnv);
    expect(octal(mode(path.join(dir, '.env')))).toBe('644');
  }, 120_000);

  it('records and restores no set-user-id bit for a .env the permissions fix narrows', async () => {
    const dir = tempDir('hma-1039-setuid-record-');
    put(dir, '.env', plainEnv, 0o4644);
    expect(mode(path.join(dir, '.env')) & 0o4000, 'the platform would not set the bit; this cell measures nothing').toBe(0o4000);

    const run = await fix(dir);
    expect(readManifest(run).modeOnlyFiles?.['.env']).toBe(0o644);

    await new HardeningScanner().rollback(dir);
    expect(octal(mode(path.join(dir, '.env')))).toBe('644');
  }, 120_000);

  it('never restores a set-user-id, set-group-id or sticky bit a store manifest records', async () => {
    const dir = tempDir('hma-1039-setuid-restore-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, '.env', plainEnv, 0o644);

    const run = await fix(dir);
    const manifest = readManifest(run);
    expect(manifest.existingFiles).toContain('config.json');
    expect(manifest.modeOnlyFiles?.['.env']).toBe(0o644);
    manifest.existingFileModes = { 'config.json': 0o4755 };
    manifest.modeOnlyFiles = { '.env': 0o7644 };
    writeFileSync(path.join(run, '.manifest.json'), JSON.stringify(manifest, null, 2));

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored).toEqual(['config.json']);
    expect(octal(mode(path.join(dir, 'config.json')))).toBe('755');
    expect(octal(mode(path.join(dir, '.env')))).toBe('644');
    expect(report.modesRestored).toEqual([{ path: '.env', mode: 0o644 }]);
  }, 120_000);

  it('consumes a run that changed nothing, so the next rollback reaches the run before it', async () => {
    const dir = tempDir('hma-1039-empty-run-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);

    await fix(dir);
    const redacted = readFileSync(path.join(dir, 'config.json'), 'utf-8');
    expect(redacted).not.toContain(FAKE_GH_TOKEN);
    const second = await fix(dir);
    const empty = readManifest(second);
    expect(empty.existingFiles, 'the second run changed a file; this cell measures nothing').toEqual([]);
    expect(empty.createdFiles).toEqual([]);
    expect(empty.modeOnlyFiles ?? {}).toEqual({});
    expect(await storeRuns(dir)).toHaveLength(2);

    const first = await new HardeningScanner().rollback(dir);
    expect(first.backupUsed).toBe(path.basename(second));
    expect(first.barrenBackups).toEqual([]);
    expect(first.restored).toEqual([]);
    expect(first.backupsBehind).toBe(1);
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(redacted);
    expect(await storeRuns(dir)).toHaveLength(1);

    const again = await new HardeningScanner().rollback(dir);
    expect(again.restored).toEqual(['config.json']);
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(tokenConfig);
  }, 120_000);

  it('takes harden-soul\'s copy only of the governance file it writes', async () => {
    const dir = tempDir('hma-1039-harden-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, '.env', plainEnv, 0o600);
    const soul = '# Soul\n\nBe helpful.\n';
    put(dir, 'SOUL.md', soul, 0o644);

    // The standalone `harden-soul` path: an external backup, then the guarded write.
    const hardening = new HardeningScanner();
    expect(await hardening.beginExternalBackup(dir)).not.toBeNull();
    const result = await new SoulScanner().hardenSoul(dir, {
      writeGuard: (rel) => hardening.ensureGovernanceBackup(dir, rel),
    });
    expect(result.writeRefused).toBeUndefined();
    expect(readFileSync(path.join(dir, 'SOUL.md'), 'utf-8'), 'harden-soul did not change SOUL.md; this cell measures nothing').not.toBe(soul);

    const run = await latestStoreRun(dir);
    expect(filesIn(run)).toEqual(['SOUL.md']);
    expect(readManifest(run).existingFiles).toEqual(['SOUL.md']);
    expect(readFileSync(path.join(run, 'SOUL.md'), 'utf-8')).toBe(soul);
  }, 120_000);
});

describe.skipIf(SKIP_MODES)('#1039 runs written by earlier versions are read as they were written', () => {
  it('restores every file a store run lists, including a copy of a file no fix changed', async () => {
    const dir = tempDir('hma-1039-earlier-store-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);

    const run = await fix(dir);
    // The shape the #376 head wrote: a copy of every candidate that existed.
    const manifest = readManifest(run);
    put(run, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o600);
    manifest.existingFiles.push('package.json');
    manifest.existingFileModes = { ...manifest.existingFileModes, 'package.json': 0o644 };
    writeFileSync(path.join(run, '.manifest.json'), JSON.stringify(manifest, null, 2));

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored).toEqual(expect.arrayContaining(['config.json', 'package.json']));
    expect(report.modesRestored).toEqual([]);
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(tokenConfig);
    expect(octal(mode(path.join(dir, 'package.json')))).toBe('644');
  }, 120_000);

  it('ignores a mode-only entry planted in a run inside the tree', async () => {
    const dir = tempDir('hma-1039-in-tree-');
    put(dir, '.env', plainEnv, 0o600);
    const run = path.join(dir, '.hackmyagent-backup', '2026-01-01T00-00-00-000Z');
    put(run, 'config.json', tokenConfig, 0o644);
    writeFileSync(path.join(run, '.manifest.json'), JSON.stringify({
      version: 2,
      existingFiles: ['config.json'],
      modeOnlyFiles: { '.env': 0o777 },
      absentAtBackup: [],
      createdFiles: [],
    }, null, 2));
    put(dir, 'config.json', '{"githubToken":"${GITHUB_TOKEN}","port":8080}\n', 0o600);

    const report = await new HardeningScanner().rollback(dir);

    expect(report.backupSource).toBe('in-tree');
    expect(report.restored).toEqual(['config.json']);
    expect(report.modesRestored).toEqual([]);
    expect(octal(mode(path.join(dir, '.env'))), 'a mode the scanned tree wrote was applied').toBe('600');
  }, 120_000);
});

/**
 * The mutation census, static half: every call that can change a file on the
 * `secure --fix` and `harden-soul` paths, pinned to the method it sits in. A new
 * site fails here until it is listed, and a site that changes the TARGET is
 * listed with the gate that must come before it in the same method.
 */
const MUTATION_CALL = /\b(?:fs|fsSync)\.(writeFile|appendFile|chmod|lchmod|unlink|rename|rm|rmdir|copyFile|cp|truncate|symlink|link|mkdir|mkdtemp|utimes|lutimes|chown|lchown|open)(?:Sync)?\(/g;

type Site = { reason: string; gate?: string };

const MUTATION_CENSUS: Record<string, Record<string, Site>> = {
  'hardening/scanner.ts': {
    'applyFixWrite:writeFile': { reason: 'every fix write to the target', gate: 'this.ensureBackupCovers(' },
    'checkFilePermissions:chmod': { reason: 'the permissions fix on the target', gate: 'this.ensureModeRecorded(' },
    'pemLooksPrivate:open': { reason: 'read-only open' },
    'jsonPrivateKeyFields:open': { reason: 'read-only open' },
    'startsWithShebang:open': { reason: 'read-only open' },
    'checkEncodedPayloads:mkdtemp': { reason: 'a scratch directory under the OS temp directory' },
    'checkEncodedPayloads:mkdir': { reason: 'inside that scratch directory' },
    'checkEncodedPayloads:writeFile': { reason: 'inside that scratch directory' },
    'checkEncodedPayloads:rm': { reason: 'removes that scratch directory' },
  },
  // The backup store and rollback, moved out of the scanner unchanged. None of
  // these writes a fix to the target: the scanner's two sites above do, behind
  // the gates this module provides.
  'hardening/backup-store.ts': {
    'copyIntoBackup:mkdir': { reason: 'the run directory in the backup store, never the target' },
    'copyIntoBackup:copyFile': { reason: 'writes the copy into the run directory; reads the target' },
    'copyIntoBackup:chmod': { reason: 'narrows the copy in the run directory to 0600' },
    'appendToBackupManifest:writeFile': { reason: 'the run manifest' },
    'recordModeOnly:writeFile': { reason: 'the run manifest' },
    'createRunBackupDir:mkdir': { reason: 'the run directory in the backup store' },
    'createBackup:writeFile': { reason: 'the run manifest' },
    'recordCreatedFiles:writeFile': { reason: 'the run manifest' },
    'restoreOneBackupFile:copyFile': { reason: 'rollback: puts a copy back' },
    'restoreOneBackupFile:chmod': { reason: 'rollback: puts a recorded mode back' },
    'restoreOneMode:chmod': { reason: 'rollback: puts a mode-only entry back' },
    'rollback:unlink': { reason: 'rollback: removes a file a fix generated, hash-verified' },
    'rollback:rm': { reason: 'rollback: removes the run it consumed' },
  },
  'soul/scanner.ts': {
    'hardenSoul:appendFileSync': { reason: 'appends governance sections to the target', gate: 'options.writeGuard(' },
    'hardenSoul:writeFileSync': { reason: 'creates the governance file in the target', gate: 'options.writeGuard(' },
  },
};

/** The method or function a line sits in: the nearest declaration above it. */
const METHOD_DECL = /^ {2}(?:(?:private|protected|public|static|async|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\(/;
const FUNCTION_DECL = /^(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/;

function mutationSites(rel: string): Array<{ key: string; line: number; declLine: number }> {
  const lines = readFileSync(path.resolve(__dirname, '../../src', rel), 'utf-8').split('\n');
  const sites: Array<{ key: string; line: number; declLine: number }> = [];
  lines.forEach((text, i) => {
    const trimmed = text.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;
    for (const m of text.matchAll(MUTATION_CALL)) {
      const call = m[0].slice(m[0].indexOf('.') + 1, -1);
      let name = '<module>';
      let declLine = 0;
      for (let j = i; j >= 0; j--) {
        const d = METHOD_DECL.exec(lines[j]) ?? FUNCTION_DECL.exec(lines[j]);
        if (d && !['if', 'for', 'while', 'switch', 'catch', 'return'].includes(d[1])) { name = d[1]; declLine = j; break; }
      }
      sites.push({ key: `${name}:${call}`, line: i, declLine });
    }
  });
  return sites;
}

describe('#1039 mutation census: every change to the target is tied to a copy or a mode-only record', () => {
  for (const [rel, census] of Object.entries(MUTATION_CENSUS)) {
    it(`${rel}: the mutation sites are the census, and each target site sits behind its gate`, () => {
      const sites = mutationSites(rel);
      const found = [...new Set(sites.map((s) => s.key))].sort();
      expect(
        found,
        'a call that can change a file was added, moved or removed. List it in MUTATION_CENSUS with what it '
        + 'changes; a call that changes the target needs a gate that takes a copy or a mode-only record first',
      ).toEqual(Object.keys(census).sort());

      const lines = readFileSync(path.resolve(__dirname, '../../src', rel), 'utf-8').split('\n');
      for (const site of sites) {
        const gate = census[site.key]?.gate;
        if (!gate) continue;
        const body = lines.slice(site.declLine, site.line + 1).join('\n');
        expect(body, `${site.key} at line ${site.line + 1} is not preceded by ${gate}`).toContain(gate);
      }
    });
  }
});

/**
 * The run-time half: a real `secure --fix` (the scan, then the governance step
 * through the same instance's guard, as the CLI runs it), with every mutation of
 * the target judged against the run's manifest at the moment it is made.
 */
describe.skipIf(SKIP_MODES)('#1039 mutation census at run time', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('each write and chmod of the target is preceded by a content copy or a mode-only record, and nothing else is copied', async () => {
    const dir = tempDir('hma-1039-census-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, '.env', plainEnv, 0o644);
    put(dir, '.env.local', plainEnv, 0o600);
    put(dir, 'SOUL.md', '# Soul\n\nBe helpful.\n', 0o644);
    put(dir, 'public/tool.py', 'print("ok")\n', 0o755);
    const storeDir = await storeDirOf(dir);
    const dirReal = realpathSync(dir);

    const snapshot = (): Map<string, { sha: string; mode: number }> => {
      const out = new Map<string, { sha: string; mode: number }>();
      const walk = (rel: string): void => {
        for (const e of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
          const r = rel ? path.join(rel, e.name) : e.name;
          if (e.isDirectory()) walk(r);
          else if (e.isFile()) {
            const p = path.join(dir, r);
            out.set(r, { sha: createHash('sha256').update(readFileSync(p)).digest('hex'), mode: mode(p) });
          }
        }
      };
      walk('');
      return out;
    };
    const before = snapshot();

    const relOf = (p: unknown): string | null => {
      if (typeof p !== 'string') return null;
      for (const root of [dir, dirReal]) {
        const r = path.relative(root, path.resolve(p));
        if (r && !r.startsWith('..') && !path.isAbsolute(r)) return r;
      }
      return null;
    };
    const latest = (): { run: string; manifest: Manifest } | null => {
      try {
        const runs = readdirSync(storeDir, { withFileTypes: true })
          .filter((e) => e.isDirectory() && !e.name.startsWith('.')).map((e) => e.name).sort();
        const run = path.join(storeDir, runs[runs.length - 1]);
        return { run, manifest: readManifest(run) };
      } catch {
        return null;
      }
    };
    const judged: Array<{ call: string; rel: string; ok: boolean; why: string }> = [];
    const judge = (call: string, p: unknown): void => {
      const rel = relOf(p);
      if (rel === null) return;
      const cur = latest();
      if (!cur) { judged.push({ call, rel, ok: false, why: 'no run manifest' }); return; }
      const m = cur.manifest;
      const copy = m.existingFiles.includes(rel) && existsSync(path.join(cur.run, rel));
      const modeOnly = Object.prototype.hasOwnProperty.call(m.modeOnlyFiles ?? {}, rel);
      let absentNow = false;
      try { lstatSync(p as string); } catch { absentNow = true; }
      const provenAbsent = [...m.absentAtBackup, ...(m.absentAtFixWrite ?? [])].includes(rel);
      let ok: boolean;
      if (call === 'chmod') ok = copy || modeOnly;
      else if (call === 'writeFile' || call === 'appendFile' || call === 'truncate') ok = copy || (absentNow && provenAbsent);
      else ok = copy;
      judged.push({ call, rel, ok, why: ok ? '' : 'no content copy or mode-only record in the run when the call was made' });
    };
    const target = trackedFs as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const DEST_ONLY = new Set(['copyFile', 'cp', 'symlink', 'link']);
    for (const name of ['writeFile', 'appendFile', 'chmod', 'lchmod', 'unlink', 'rename', 'rm', 'rmdir', 'copyFile', 'cp', 'truncate', 'symlink', 'link', 'utimes', 'lutimes']) {
      const original = target[name];
      if (typeof original !== 'function') continue;
      vi.spyOn(target, name).mockImplementation(async (...args: unknown[]) => {
        if (DEST_ONLY.has(name)) judge(name, args[1]);
        else {
          judge(name, args[0]);
          if (name === 'rename') judge(name, args[1]);
        }
        return original(...args);
      });
    }

    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: dir, autoFix: true });
    vi.restoreAllMocks();
    const hardened = await new SoulScanner().hardenSoul(dir, {
      writeGuard: (rel) => scanner.ensureGovernanceBackup(dir, rel),
    });
    expect(hardened.writeRefused).toBeUndefined();
    await scanner.recordCreatedFiles(dir, result.backupPath, [hardened.file]);

    expect(judged.filter((j) => j.call === 'chmod').map((j) => j.rel), 'the census saw no chmod; it measures nothing').toContain('.env');
    expect(judged.filter((j) => j.call === 'writeFile').map((j) => j.rel), 'the census saw no write; it measures nothing').toContain('config.json');
    expect(judged.filter((j) => !j.ok)).toEqual([]);

    // Everything that differs afterwards is tied to a record, and the run holds
    // a copy of nothing else.
    const after = snapshot();
    const run = await latestStoreRun(dir);
    const m = readManifest(run);
    const changedContent: string[] = [];
    for (const [rel, was] of before) {
      const now = after.get(rel);
      if (!now || now.sha !== was.sha) {
        changedContent.push(rel);
        expect(m.existingFiles, `${rel} changed and the run holds no copy of it`).toContain(rel);
        expect(createHash('sha256').update(readFileSync(path.join(run, rel))).digest('hex'), `${rel}: the copy is not the pre-fix bytes`).toBe(was.sha);
        expect(m.existingFileModes?.[rel], `${rel}: the copy did not record the pre-fix mode`).toBe(was.mode & 0o777);
      } else if (now.mode !== was.mode) {
        expect(m.modeOnlyFiles?.[rel], `${rel}: only its mode changed and no mode-only entry records it`).toBe(was.mode & 0o777);
      }
    }
    for (const rel of after.keys()) {
      if (before.has(rel)) continue;
      expect([...m.absentAtBackup, ...(m.absentAtFixWrite ?? [])], `${rel} was created and never proven absent`).toContain(rel);
    }
    expect(changedContent).toEqual(expect.arrayContaining(['config.json', 'SOUL.md']));
    expect(filesIn(run), 'the run holds a copy of a file no fix changed').toEqual([...changedContent].sort());
    expect(m.existingFiles.slice().sort()).toEqual([...changedContent].sort());
  }, 120_000);
});
