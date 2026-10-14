/**
 * The `check` command's retry queue, ~/.opena2a/hma-pending-scans.json, is
 * readable and writable by its owner only (0600).
 *
 * Its two writers in src/cli.ts, queuePendingScan and flushPendingScans,
 * passed no mode, so under a umask of 022 the queue was created 0644, while
 * writeConfig in opt-in.ts writes config.json 0600. Both now go through
 * `writePendingScans`.
 *
 * The cells that read a mode set the umask to 022, under which a file created
 * with no mode is 0644, so the result does not depend on the umask of the
 * shell that runs the suite.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { getPendingScansPath, writePendingScans } from '../../src/telemetry/pending-scans';

// While `chmod.fails` is set, chmodSync in src/telemetry/pending-scans.ts
// throws, as it can on a file another user owns, so a cell reads the mode the
// file was created with: the one that holds before the chmod runs.
const chmod = vi.hoisted(() => ({ fails: false }));
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return {
    ...actual,
    chmodSync: (...args: Parameters<typeof actual.chmodSync>) => {
      if (chmod.fails) throw Object.assign(new Error('EPERM: operation not permitted, chmod'), { code: 'EPERM' });
      return actual.chmodSync(...args);
    },
  };
});

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const QUEUE = 'hma-pending-scans.json';
const savedOpena2aHome = process.env.OPENA2A_HOME;

let savedUmask: number | undefined;

function restoreEnv(): void {
  if (savedOpena2aHome === undefined) delete process.env.OPENA2A_HOME;
  else process.env.OPENA2A_HOME = savedOpena2aHome;
  if (savedUmask !== undefined) process.umask(savedUmask);
  savedUmask = undefined;
  chmod.fails = false;
}

function umask022(): void {
  savedUmask = process.umask(0o022);
}

const modeOf = (p: string): string => (fs.statSync(p).mode & 0o777).toString(8);

describe.skipIf(process.platform === 'win32')('the pending-scans queue file is mode 0600', () => {
  afterEach(restoreEnv);

  it('resolves under OPENA2A_HOME', () => {
    const home = tempDir('hma-pending-home-');
    process.env.OPENA2A_HOME = home;
    expect(getPendingScansPath()).toBe(path.join(home, QUEUE));
  });

  it('a new queue file, and the directory it goes in, are created with the file at 0600', () => {
    umask022();
    const queue = path.join(tempDir('hma-pending-home-'), '.opena2a', QUEUE);
    writePendingScans(queue, [{ name: 'fixture-pkg' }]);
    expect(JSON.parse(fs.readFileSync(queue, 'utf-8'))).toEqual([{ name: 'fixture-pkg' }]);
    expect(modeOf(queue)).toBe('600');
  });

  it('a new queue file is 0600 from the moment it is created, before the chmod runs', () => {
    umask022();
    chmod.fails = true;
    const queue = path.join(tempDir('hma-pending-home-'), QUEUE);
    writePendingScans(queue, [{ name: 'fixture-pkg' }]);
    expect(JSON.parse(fs.readFileSync(queue, 'utf-8'))).toEqual([{ name: 'fixture-pkg' }]);
    expect(modeOf(queue)).toBe('600');
  });

  it('a queue file an earlier version left at 0644 is rewritten at 0600', () => {
    umask022();
    const queue = path.join(tempDir('hma-pending-home-'), QUEUE);
    fs.writeFileSync(queue, '[]');
    fs.chmodSync(queue, 0o644);
    expect(modeOf(queue)).toBe('644');

    writePendingScans(queue, [{ name: 'fixture-pkg' }]);

    expect(JSON.parse(fs.readFileSync(queue, 'utf-8'))).toEqual([{ name: 'fixture-pkg' }]);
    expect(modeOf(queue)).toBe('600');
  });
});

// The two writers in src/cli.ts are called only when stdin is a terminal, so
// they are held to the shared writer by their source.
describe('every writer of the pending-scans queue in src/cli.ts goes through writePendingScans', () => {
  function srcFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) out.push(...srcFiles(full));
      else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) out.push(full);
    }
    return out;
  }

  it('the queue file name is spelled, as a string, in pending-scans.ts only', () => {
    const spelled = /['"`]hma-pending-scans\.json/;
    const naming = srcFiles(path.join(REPO_ROOT, 'src'))
      .filter(f => spelled.test(fs.readFileSync(f, 'utf-8')))
      .map(f => path.relative(REPO_ROOT, f).split(path.sep).join('/'));
    expect(naming).toEqual(['src/telemetry/pending-scans.ts']);
  });

  // A call that writes a file, whatever `fs` is bound to: a member of `fs`,
  // `fs.promises` or require('fs'), or a name imported from either module.
  const RAW_WRITE = /\b(?:writeFile|appendFile|copyFile|rename|open|createWriteStream|cp)(?:Sync)?\s*\(/;

  it('the raw-write pattern this cell relies on matches each way of writing the file', () => {
    for (const write of [
      "fs.writeFileSync(p, '[]')",
      "fs.writeFile(p, '[]', () => {})",
      "fs.promises.writeFile(p, '[]')",
      "fsp.writeFile(p, '[]')",
      "require('fs').writeFileSync(p, '[]')",
      "writeFile(p, '[]')",
      "appendFileSync(p, '[]')",
      "createWriteStream(p).end('[]')",
      'renameSync(tmp, p)',
    ]) {
      expect(write).toMatch(RAW_WRITE);
    }
    expect('try { writePendingScans(p, remaining); } catch { /* Non-fatal */ }').not.toMatch(RAW_WRITE);
    expect("queue = JSON.parse(fs.readFileSync(p, 'utf-8'));").not.toMatch(RAW_WRITE);
  });

  it.each(['queuePendingScan', 'flushPendingScans'])('%s in src/cli.ts writes through writePendingScans and nothing else', fn => {
    const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf-8');
    const start = cli.search(new RegExp(`function ${fn}\\(`));
    expect(start).toBeGreaterThan(-1);
    const body = cli.slice(start, cli.indexOf('\n}\n', start));
    expect(body).toContain('writePendingScans(');
    expect(body).not.toMatch(RAW_WRITE);
  });
});
