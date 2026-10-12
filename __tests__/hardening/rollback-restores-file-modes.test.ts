/**
 * #376 — `rollback` puts back each file's mode, not the mode of its copy.
 *
 * The copies in the backup store are narrowed to `0600`, and `copyFile` gives
 * the restored file the copy's mode. Measured before each run recorded the
 * modes: after `--fix` then `rollback`, a `0755` `public/tool.py` and a `0644`
 * `config.json` both read `-rw-------`, a `.env` the permissions fix had
 * narrowed from `0644` stayed `0600`, and `config/production.json`, first
 * copied when a fix wrote it, came back `0600` instead of `0640`. 0.33.2 kept
 * its copies in the tree at their own modes, so its rollback restored all four.
 *
 * Each store run's `.manifest.json` now carries `existingFileModes`, and the
 * restore applies it. A run inside the tree (`.hackmyagent-backup/`, written by
 * 0.33.2 and earlier) is read as before: no release wrote the field there, so
 * one found there was written by the scanned tree and is ignored.
 */
import { describe, it, expect } from 'vitest';
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun } from '../helpers/backup-store';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'b'.repeat(36)}`;

const mode = (p: string): number => statSync(p).mode & 0o7777;
const octal = (m: number): string => m.toString(8);

function put(dir: string, rel: string, content: string, fileMode: number): void {
  const p = path.join(dir, rel);
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, content);
  chmodSync(p, fileMode);
}

const tokenConfig = `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`;

interface Manifest {
  version?: number;
  existingFiles: string[];
  createdFiles: unknown[];
  existingFileModes?: Record<string, number>;
}

const readManifest = (run: string): Manifest =>
  JSON.parse(readFileSync(path.join(run, '.manifest.json'), 'utf-8')) as Manifest;

async function fix(dir: string, rel = 'config.json'): Promise<string> {
  await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
  expect(readFileSync(path.join(dir, rel), 'utf-8'), 'the fix did not redact the credential; this cell measures nothing')
    .not.toContain(FAKE_GH_TOKEN);
  return latestStoreRun(dir);
}

describe.skipIf(process.platform === 'win32')('#376 rollback restores each file\'s mode from a store run', () => {
  it('restores a 0755 script and a 0644 config from 0600 copies, with 493 and 420 recorded', async () => {
    const dir = tempDir('hma-376-modes-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, 'public/tool.py', 'print("ok")\n', 0o755);

    const run = await fix(dir);
    const manifest = readManifest(run);
    expect(manifest.version).toBe(2);
    expect(manifest.existingFiles).toEqual(expect.arrayContaining(['config.json', 'public/tool.py']));
    expect(manifest.createdFiles.length, 'no created file was recorded, so the rewrite through the parse is not exercised').toBeGreaterThan(0);
    expect(manifest.existingFileModes?.['public/tool.py'], 'the script\'s mode was not recorded').toBe(493);
    expect(manifest.existingFileModes?.['config.json'], 'the config\'s mode was not recorded').toBe(420);
    expect(octal(mode(path.join(run, 'public/tool.py'))), 'a copy in the store is readable by others').toBe('600');
    expect(octal(mode(path.join(run, 'config.json')))).toBe('600');

    const report = await new HardeningScanner().rollback(dir);

    expect(report.backupSource).toBe('store');
    expect(report.restored).toEqual(expect.arrayContaining(['config.json', 'public/tool.py']));
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(tokenConfig);
    expect(octal(mode(path.join(dir, 'public/tool.py'))), 'the script lost its execute bit').toBe('755');
    expect(octal(mode(path.join(dir, 'config.json')))).toBe('644');
    expect(octal(mode(path.join(dir, 'package.json'))), 'a file no fix touched came back at the copy\'s mode').toBe('644');
  }, 120_000);

  it('undoes the permissions fix on a 0644 .env', async () => {
    const dir = tempDir('hma-376-modes-env-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, '.env', `GITHUB_TOKEN=${FAKE_GH_TOKEN}\n`, 0o644);

    const run = await fix(dir);
    expect(octal(mode(path.join(dir, '.env'))), 'the permissions fix did not narrow .env; this cell measures nothing').toBe('600');
    expect(readManifest(run).existingFileModes?.['.env']).toBe(420);

    await new HardeningScanner().rollback(dir);

    expect(octal(mode(path.join(dir, '.env'))), 'rollback did not undo the permissions fix').toBe('644');
  }, 120_000);

  it('restores a file first copied when a fix wrote it at 0640', async () => {
    const dir = tempDir('hma-376-modes-fixwrite-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config/production.json', tokenConfig, 0o640);

    const run = await fix(dir, 'config/production.json');
    const manifest = readManifest(run);
    expect(manifest.existingFiles, 'config/production.json is not in the run').toContain('config/production.json');
    expect(manifest.existingFileModes?.['config/production.json']).toBe(416);
    expect(octal(mode(path.join(run, 'config/production.json')))).toBe('600');

    await new HardeningScanner().rollback(dir);

    expect(readFileSync(path.join(dir, 'config/production.json'), 'utf-8')).toBe(tokenConfig);
    expect(octal(mode(path.join(dir, 'config/production.json')))).toBe('640');
  }, 120_000);

  it('restores at the copy\'s mode when a store run\'s recorded mode is missing or not a mode', async () => {
    const dir = tempDir('hma-376-modes-invalid-');
    put(dir, 'package.json', '{"name":"p","version":"1.0.0"}\n', 0o644);
    put(dir, 'config.json', tokenConfig, 0o644);
    put(dir, 'public/tool.py', 'print("ok")\n', 0o755);
    put(dir, 'public/page.html', '<p>ok</p>\n', 0o644);

    const run = await fix(dir);
    const manifestPath = path.join(run, '.manifest.json');
    const manifest = readManifest(run);
    // 4096 is one past chmod's range and would clear every permission bit;
    // a string and a fraction are not integers; package.json has no entry.
    manifest.existingFileModes = { 'config.json': 4096, 'public/tool.py': '493' as unknown as number, 'public/page.html': 420.5 };
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored).toEqual(expect.arrayContaining(['config.json', 'public/tool.py', 'public/page.html', 'package.json']));
    for (const rel of ['config.json', 'public/tool.py', 'public/page.html', 'package.json']) {
      expect(octal(mode(path.join(dir, rel))), `${rel} was not restored at its copy's mode`).toBe('600');
    }
  }, 120_000);
});

describe.skipIf(process.platform === 'win32')('#376 a run inside the tree is restored as 0.33.2 restored it', () => {
  /** A run as 0.33.2 wrote it: in the tree, copies at the modes they were taken at, no recorded modes. */
  function inTreeRun(dir: string, extra: Record<string, unknown> = {}): string {
    const run = path.join(dir, '.hackmyagent-backup', '2026-01-01T00-00-00-000Z');
    put(run, 'config.json', tokenConfig, 0o644);
    put(run, 'public/tool.py', 'print("ok")\n', 0o755);
    writeFileSync(path.join(run, '.manifest.json'), JSON.stringify({
      version: 2,
      existingFiles: ['config.json', 'public/tool.py'],
      absentAtBackup: [],
      createdFiles: [],
      ...extra,
    }, null, 2));
    // The live tree after a fix: the token replaced, the script narrowed.
    put(dir, 'config.json', '{"githubToken":"${GITHUB_TOKEN}","port":8080}\n', 0o600);
    put(dir, 'public/tool.py', 'print("changed")\n', 0o600);
    return run;
  }

  it('restores an archive written by 0.33.2 at its copies\' modes', async () => {
    const dir = tempDir('hma-376-modes-legacy-');
    inTreeRun(dir);

    const report = await new HardeningScanner().rollback(dir);

    expect(report.backupSource).toBe('in-tree');
    expect(report.restored).toEqual(expect.arrayContaining(['config.json', 'public/tool.py']));
    expect(readFileSync(path.join(dir, 'config.json'), 'utf-8')).toBe(tokenConfig);
    expect(octal(mode(path.join(dir, 'config.json')))).toBe('644');
    expect(octal(mode(path.join(dir, 'public/tool.py')))).toBe('755');
  }, 120_000);

  it('ignores recorded modes planted in an in-tree manifest, so 511 never opens a file to everyone', async () => {
    const dir = tempDir('hma-376-modes-planted-');
    inTreeRun(dir, { existingFileModes: { 'config.json': 511, 'public/tool.py': 511 } });

    const report = await new HardeningScanner().rollback(dir);

    expect(report.backupSource).toBe('in-tree');
    expect(report.restored).toEqual(expect.arrayContaining(['config.json', 'public/tool.py']));
    expect(octal(mode(path.join(dir, 'config.json'))), 'a mode the scanned tree wrote was applied').toBe('644');
    expect(octal(mode(path.join(dir, 'public/tool.py')))).toBe('755');
  }, 120_000);
});
