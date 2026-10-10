/**
 * With the generative analyst installed and its daemon stopped, `nanomind
 * status` and `secure --nanomind` say so and name `nanomind-analyst start`.
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
import { mkdirSync, writeFileSync } from 'node:fs';
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

/** Spawn the CLI with no daemon on the socket and the analyst installed or not. */
function run(installed: boolean, args: string[], cwd: string = tempDir('hma-analyst-cwd-')): Run {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home(installed),
    NO_COLOR: '1',
    NODE_OPTIONS: `--require ${JSON.stringify(PRELOAD)}`,
    NANOMIND_GUARD_SOCK: path.join(tempDir('hma-analyst-sock-'), 'daemon.sock'),
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
