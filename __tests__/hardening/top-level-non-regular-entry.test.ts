/**
 * `secure` never finished when a top-level entry of the scanned tree was not a
 * regular file.
 *
 * SEC-003 and the 27 source checks read every top-level entry that was not a
 * directory, and `readFile` on a FIFO with no writer blocks forever. Only a
 * regular file, or a symbolic link whose `stat` target is one, is opened now;
 * each other entry (a FIFO, a socket, a device, a link to one) is named under
 * `coverage.skippedEntries` and on one report line, so the scan completes.
 *
 *   (a) a top-level FIFO beside a source file: the scan finishes, SEC-003 and
 *       LOG-002 judge the readable file, and the FIFO is named;
 *   (b) a top-level `.js` link to that FIFO: not opened, named as a link;
 *   (c) a tree with only regular files: no `skippedEntries` key;
 *   (d) through the built CLI: a verdict, exit code settled, and a coverage
 *       line naming the FIFO.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { ScanResult } from '../../src/hardening/security-check';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const PROBE_PACKAGE = '{"name":"probe","version":"1.0.0"}\n';
const LOGS_PASSWORD = 'export function login(password: string): void { console.log(password); }\n';
const ROTATES = '// rotate the signing key every 30 days\nexport const KEY_VERSION = 2;\n';

const canMkfifo = process.platform !== 'win32' && spawnSync('mkfifo', ['--version']).error === undefined;

function project(files: Record<string, string>, fifos: string[] = []): string {
  const dir = tempDir('hma-fifo-');
  for (const [rel, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), content);
  for (const name of fifos) {
    const made = spawnSync('mkfifo', [path.join(dir, name)]);
    if (made.status !== 0) throw new Error(`mkfifo failed: ${made.stderr}`);
  }
  return dir;
}

function scan(dir: string): Promise<ScanResult> {
  return new HardeningScanner().scan({ targetDir: dir });
}

function record(result: ScanResult, checkId: string) {
  return (result.allFindings ?? []).find((f) => f.checkId === checkId);
}

describe.skipIf(!canMkfifo)('a top-level entry that is not a regular file', () => {
  it('(a) a top-level FIFO: the scan finishes, the readable files are judged, the FIFO is named', async () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'index.ts': LOGS_PASSWORD, 'keys.ts': ROTATES }, ['pipe']);
    const result = await scan(dir);
    expect(record(result, 'SEC-003')).toMatchObject({ passed: true });
    expect(record(result, 'LOG-002')).toMatchObject({ passed: false, file: 'index.ts' });
    expect(result.coverage?.skippedEntries).toEqual([{ path: 'pipe', type: 'FIFO' }]);
    expect(result.coverage?.unreadableInputs?.count ?? 0).toBe(0);
  }, 60_000);

  it('(a) a FIFO alone at the root leaves SEC-003 with nothing to read, not a failure', async () => {
    const dir = project({}, ['pipe']);
    const result = await scan(dir);
    expect(record(result, 'SEC-003')?.passed).not.toBe(false);
    expect(result.coverage?.skippedEntries).toEqual([{ path: 'pipe', type: 'FIFO' }]);
  }, 60_000);

  it('(b) a top-level .js link to a FIFO is not opened and is named as a link', async () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'index.ts': LOGS_PASSWORD }, ['pipe']);
    fs.symlinkSync('pipe', path.join(dir, 'pipe.js'));
    const result = await scan(dir);
    expect(record(result, 'LOG-002')).toMatchObject({ passed: false, file: 'index.ts', details: { files: ['index.ts'] } });
    // Listing order is the filesystem's, so compare by name.
    const named = [...(result.coverage?.skippedEntries ?? [])].sort((x, y) => x.path.localeCompare(y.path));
    expect(named).toEqual([
      { path: 'pipe', type: 'FIFO' },
      { path: 'pipe.js', type: 'symbolic link to a FIFO' },
    ]);
  }, 60_000);

  it('(c) a tree of regular files carries no skippedEntries key', async () => {
    const result = await scan(project({ 'package.json': PROBE_PACKAGE, 'index.ts': LOGS_PASSWORD }));
    expect(result.coverage).not.toHaveProperty('skippedEntries');
  }, 60_000);
});

describe.skipIf(!canMkfifo)('through the built CLI', () => {
  beforeAll(assertDistFresh);

  it('(d) secure on a tree with a top-level FIFO completes with a verdict and a coverage line naming it', () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'index.ts': 'export const answer = 42;\n' }, ['pipe']);
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: tempDir('hma-fifo-home-') };
    delete env.ANTHROPIC_API_KEY;
    const run = spawnSync(
      process.execPath,
      [BUILT_CLI, 'secure', dir, '--ci', '--no-registry', '--no-contribute', '--static-only'],
      { encoding: 'utf-8', env, timeout: 180_000 },
    );
    expect(run.error).toBeUndefined();
    expect(run.signal).toBeNull();
    expect([0, 1]).toContain(run.status);
    const text = run.stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(text).toMatch(/Not read\s+pipe\s+\(FIFO, not a regular file\)/);
    expect(text).toMatch(/Verdict\s+\S/);
  }, 200_000);
});
