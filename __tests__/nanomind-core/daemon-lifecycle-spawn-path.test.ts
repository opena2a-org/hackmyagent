/**
 * The NanoMind daemon is started from an absolute path, never from a command
 * name looked up on PATH.
 *
 * `ensureDaemon()` used to fall back to `spawn('nanomind-daemon', ['start'])`
 * when no daemon CLI sat next to HMA, and started the development checkout
 * with `spawn('node', ...)`. Both names were resolved on PATH, so whatever
 * executable of that name came first on PATH was what ran. The start command
 * is now the Node binary already running HMA plus a daemon CLI found relative
 * to this package.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

const spawnCalls: Array<{ command: string; args: string[] }> = [];

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    spawn: vi.fn((command: string, args: string[]) => {
      spawnCalls.push({ command, args });
      // Reports a failed launch, so ensureDaemon() returns once the command
      // is recorded instead of waiting on a daemon this mock never starts.
      return {
        unref() {},
        on(event: string, listener: () => void) {
          if (event === 'error') queueMicrotask(listener);
          return this;
        },
        kill() {},
        killed: false,
      };
    }),
  };
});

import { ensureDaemon, resolveDaemonCommand, SIBLING_DAEMON_CLI } from '../../src/nanomind-core/daemon-lifecycle';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

function writeFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

describe('NanoMind daemon start command', () => {
  let root: string;

  beforeEach(() => {
    spawnCalls.length = 0;
    root = realpathSync(mkdtempSync(join(tmpdir(), 'hma-daemon-path-')));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('ensureDaemon never spawns a command name resolved on PATH', async () => {
    await ensureDaemon(await freePort());

    const commands = spawnCalls.map((call) => call.command);
    expect(commands).not.toContain('nanomind-daemon');
    expect(commands).not.toContain('node');
    for (const call of spawnCalls) {
      expect(call.command).toBe(process.execPath);
      expect(isAbsolute(call.args[0])).toBe(true);
    }
  });

  it('runs an installed @nanomind/daemon bin with the current Node binary', () => {
    const pkgDir = join(root, 'project', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: { 'nanomind-daemon': 'lib/cli.js' },
    }));
    writeFile(join(pkgDir, 'lib', 'cli.js'), '');
    const baseDir = join(root, 'project', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toEqual({
      command: '/opt/node/bin/node',
      args: [join(pkgDir, 'lib', 'cli.js'), 'start'],
    });
  });

  it('accepts a bin field given as a single path', () => {
    const pkgDir = join(root, 'project', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: 'bin/daemon.js',
    }));
    writeFile(join(pkgDir, 'bin', 'daemon.js'), '');
    const baseDir = join(root, 'project', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')?.args).toEqual([
      join(pkgDir, 'bin', 'daemon.js'),
      'start',
    ]);
  });

  it('prefers the monorepo sibling checkout during development', () => {
    const cli = join(root, SIBLING_DAEMON_CLI);
    writeFile(cli, '');
    const baseDir = join(root, 'workspace', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toEqual({
      command: '/opt/node/bin/node',
      args: [cli, 'start'],
    });
  });

  it('returns null when the installed package names a bin file that is missing', () => {
    const pkgDir = join(root, 'project', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: { 'nanomind-daemon': 'lib/cli.js' },
    }));
    const baseDir = join(root, 'project', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toBeNull();
  });

  // The package is found the way Node finds HMA's own dependencies, which
  // includes the node_modules directories above HMA's own. A global HMA
  // install therefore finds a global daemon install beside it.
  it('runs a global @nanomind/daemon install when HMA is installed globally too', () => {
    const pkgDir = join(root, 'prefix', 'lib', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: { 'nanomind-daemon': 'lib/cli.js' },
    }));
    writeFile(join(pkgDir, 'lib', 'cli.js'), '');
    const baseDir = join(root, 'prefix', 'lib', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')?.args).toEqual([
      join(pkgDir, 'lib', 'cli.js'),
      'start',
    ]);
  });

  it.each([
    ['a relative path that climbs out', '../../outside.js'],
    ['a bin map entry that climbs out', { 'nanomind-daemon': '../../outside.js' }],
  ])('returns null when the package bin is %s of the package directory', (_label, bin) => {
    const pkgDir = join(root, 'project', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({ name: '@nanomind/daemon', bin }));
    // The file the bin value points at exists, so only the confinement
    // check stands between it and the Node binary.
    writeFile(join(root, 'project', 'node_modules', 'outside.js'), '');
    const baseDir = join(root, 'project', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toBeNull();
  });

  it('returns null when the package bin is a link to a file outside the package directory', () => {
    const pkgDir = join(root, 'project', 'node_modules', '@nanomind', 'daemon');
    writeFile(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: { 'nanomind-daemon': 'lib/cli.js' },
    }));
    const outside = join(root, 'elsewhere', 'cli.js');
    writeFile(outside, '');
    mkdirSync(join(pkgDir, 'lib'), { recursive: true });
    symlinkSync(outside, join(pkgDir, 'lib', 'cli.js'));
    const baseDir = join(root, 'project', 'node_modules', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toBeNull();
  });

  it('returns null when no daemon CLI is installed next to HMA', () => {
    const baseDir = join(root, 'workspace', 'hackmyagent', 'dist', 'nanomind-core');

    expect(resolveDaemonCommand(baseDir, '/opt/node/bin/node')).toBeNull();
  });
});
