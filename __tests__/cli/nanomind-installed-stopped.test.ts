/**
 * With the generative analyst installed and its daemon stopped, `nanomind
 * status`, `nanomind setup` and `secure --nanomind` say so and name
 * `nanomind-analyst start`. Setup also leaves the install as it is.
 *
 * The daemon stops by itself when idle, so "installed, not running" is the
 * ordinary state of a finished install. Both commands used to print what they
 * print on a machine with no analyst at all, measured on a home directory
 * holding the launchd agent and no daemon:
 *
 *   nanomind status      Daemon:    not running
 *                        Run: hackmyagent nanomind setup
 *   secure --nanomind    Model not set up. Run: hackmyagent nanomind setup
 *
 * "Not set up" is false for a finished install, and setup is the wrong
 * command: it runs the install again.
 *
 * The CLI is spawned, because the claim is what a person reads in a terminal
 * and the exit code that goes with it. A preload places the install where the
 * test builds it (see the fixture); each cell varies only whether the launchd
 * agent file is there, with the socket absent in both.
 *
 * RED-ON-BASE cells fail on the build before the fix; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(REPO_ROOT, '__tests__', 'fixtures', 'stub-analyst-install-preload.cjs');

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** A home directory, with the launchd agent `nanomind-analyst install` writes when `installed`. */
function home(installed: boolean): string {
  const dir = tempDir('hma-analyst-home-');
  if (installed) {
    const agents = path.join(dir, 'Library', 'LaunchAgents');
    mkdirSync(agents, { recursive: true });
    writeFileSync(path.join(agents, 'org.opena2a.nanomind-analyst.plist'), '<plist version="1.0"/>\n');
  }
  return dir;
}

function fixture(): string {
  const dir = tempDir('hma-analyst-target-');
  writeFileSync(path.join(dir, 'agent.md'), '# Notes agent\n\nSummarises meeting notes for the team.\n');
  return dir;
}

/** A user-owned PATH dir holding a nanomind-analyst that records how it was called. */
function installerShim(): { dir: string; sentinel: string } {
  const dir = tempDir('hma-analyst-shim-');
  const sentinel = path.join(dir, 'shim-fired');
  const shim = path.join(dir, 'nanomind-analyst');
  writeFileSync(shim, `#!/bin/sh\necho "$@" > "${sentinel}"\nexit 0\n`);
  chmodSync(shim, 0o755);
  chmodSync(dir, 0o755);
  return { dir, sentinel };
}

/** PATH with `dir` searched first, so its nanomind-analyst shadows any other. */
function pathWith(dir: string): string {
  return `${dir}${path.delimiter}${process.env.PATH ?? ''}`;
}

/** Spawn the CLI with no daemon on the socket and the analyst installed or not. */
function run(
  installed: boolean,
  args: string[],
  cwd: string = tempDir('hma-analyst-cwd-'),
  searchPath: string | undefined = process.env.PATH,
): Run {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PATH: searchPath,
    HOME: home(installed),
    NO_COLOR: '1',
    NODE_OPTIONS: `--require ${JSON.stringify(PRELOAD)}`,
    // Under /tmp, not TMPDIR: past sun_path (104 bytes on macOS) connect()
    // fails with EINVAL rather than ENOENT, and a long TMPDIR gets there.
    NANOMIND_GUARD_SOCK: path.join(tempDir('hma-analyst-sock-', '/tmp'), 'daemon.sock'),
  };
  delete env.HMA_CLI_PREFIX;
  delete env.OPENA2A_HOME;
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: 'utf8' });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** The lines of the scan's analyst block that say why the analyst produced nothing. */
const ANALYST_LINES = /^ {2}(Analyst installed, daemon stopped\.|Start: {2}nanomind-analyst start|Verify: hackmyagent nanomind status|Model not set up\.).*\n/gm;

beforeAll(() => {
  assertDistFresh();
});

describe('nanomind status', () => {
  it('RED-ON-BASE: an installed analyst with a stopped daemon is reported as installed and stopped, with `nanomind-analyst start`', () => {
    const res = run(true, ['nanomind', 'status']);

    expect(res.stdout).toContain('  Daemon:    installed, stopped\n');
    expect(res.stdout).toContain('\nStart it: nanomind-analyst start\n');
    expect(res.stdout).not.toMatch(/not set up/i);
    expect(res.stdout).not.toContain('nanomind setup');
    expect(res.status).toBe(0);
  });

  it('PIN: with no analyst installed it still points at setup', () => {
    const res = run(false, ['nanomind', 'status']);

    expect(res.stdout).toContain('  Daemon:    not running\n');
    expect(res.stdout).toContain('\nRun: hackmyagent nanomind setup\n');
    expect(res.stdout).not.toContain('nanomind-analyst start');
    expect(res.status).toBe(0);
  });
});

describe('nanomind setup', () => {
  it('RED-ON-BASE: an installed analyst with a stopped daemon is reported as installed and stopped, with `nanomind-analyst start`, and the install is not run again', () => {
    const { dir, sentinel } = installerShim();
    const res = run(true, ['nanomind', 'setup'], undefined, pathWith(dir));

    expect(res.stderr).toContain(
      'NanoMind analyst is installed and its daemon is stopped.\n'
      + 'Start it: nanomind-analyst start\n'
      + 'Verify:   hackmyagent nanomind status\n',
    );
    expect(existsSync(sentinel)).toBe(false);
    expect(res.stderr).not.toContain('Running: nanomind-analyst install');
    expect(res.status).toBe(0);
  });

  it('RED-ON-BASE: with the installer not on PATH, an installed analyst gets no install instructions', () => {
    // An empty directory as the whole PATH: no installer can be found, and
    // none on the machine running the test can be run.
    const res = run(true, ['nanomind', 'setup'], undefined, tempDir('hma-analyst-empty-path-'));

    expect(res.stderr).toContain('Start it: nanomind-analyst start\n');
    expect(res.stderr).not.toContain('installer is not on PATH');
    expect(res.stderr).not.toContain('pip install');
    expect(res.status).toBe(0);
  });

  it('PIN: with no analyst installed it still runs the install (darwin)', () => {
    if (process.platform !== 'darwin') {
      return; // the installer is looked up only on darwin
    }
    const { dir, sentinel } = installerShim();
    const res = run(false, ['nanomind', 'setup'], undefined, pathWith(dir));

    expect(res.stderr).toContain('Running: nanomind-analyst install\n');
    expect(readFileSync(sentinel, 'utf8')).toBe('install\n');
    expect(res.stderr).not.toContain('nanomind-analyst start');
    expect(res.status).toBe(0);
  });
});

describe('secure --nanomind', () => {
  // One target for both runs: the comparison below is of everything the scan
  // prints about it.
  const target = fixture();
  let stopped: Run;
  let absent: Run;

  beforeAll(() => {
    stopped = run(true, ['secure', '.', '--nanomind'], target);
    absent = run(false, ['secure', '.', '--nanomind'], target);
  });

  it('RED-ON-BASE: an installed analyst with a stopped daemon is reported as installed and stopped, with `nanomind-analyst start`', () => {
    expect(stopped.stdout).toContain(
      '  Analyst installed, daemon stopped. No per-finding analysis ran on this scan.\n'
      + '  Start:  nanomind-analyst start\n'
      + '  Verify: hackmyagent nanomind status\n',
    );
    expect(stopped.stderr).toContain(
      'NanoMind analyst is installed and its daemon is stopped. Start it: nanomind-analyst start\n',
    );
    for (const stream of [stopped.stdout, stopped.stderr]) {
      expect(stream).not.toMatch(/not set up/i);
      expect(stream).not.toContain('nanomind setup');
    }
  });

  it('PIN: with no analyst installed it still points at setup', () => {
    expect(absent.stdout).toContain('  Model not set up. Run: hackmyagent nanomind setup\n');
    expect(absent.stderr).toContain('NanoMind generative model not set up. Run: hackmyagent nanomind setup\n');
    for (const stream of [absent.stdout, absent.stderr]) {
      expect(stream).not.toContain('nanomind-analyst start');
    }
  });

  it('PIN: the two states differ in those lines only — same exit code, same score, same findings', () => {
    expect(stopped.status).toBe(absent.status);
    expect(stopped.stdout.replace(ANALYST_LINES, '')).toBe(absent.stdout.replace(ANALYST_LINES, ''));
    // The block was there to cut in both runs, and the rest is a whole scan.
    expect(stopped.stdout).toMatch(ANALYST_LINES);
    expect(absent.stdout).toMatch(ANALYST_LINES);
    expect(absent.stdout).toMatch(/Security\s.*\d+\/100/);
  });
});
