/**
 * #741 — `-v` after a subcommand name is that subcommand's `--verbose`.
 *
 * The program registers `-v, --version`, and Commander's default mode
 * recognises program options anywhere on the line, so `secure -v <dir>`
 * matched the program's `-v` before `secure` ever saw its own: the version
 * line printed, the process exited 0, and no scan ran, while
 * `secure --help` documented `-v, --verbose`. Same for `check`, `scan-soul`,
 * `scan`, `attack`, `fix-all` and `wild` (whose help cited `wild -v` without
 * registering it).
 *
 * Positional options fix the precedence: program options are recognised only
 * before the subcommand name. The one program option, `--no-color`, therefore
 * has to keep working after the subcommand name by another route, and the
 * root-level `-v` / `--version` must keep printing the version.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const VERSION_LINE = /^hackmyagent \d+\.\d+\.\d+/m;

const ROOT = mkdtempSync(join(tmpdir(), 'hma-short-verbose-'));
const EMPTY_DIR = join(ROOT, 'empty');
const SOUL_FILE = join(ROOT, 'SOUL.md');
// Isolated config dir so an ambient `telemetry off` on the developer's
// machine cannot change what the spawn prints (see version-stream-split).
const XDG_CONFIG_HOME = join(ROOT, 'xdg');
mkdirSync(EMPTY_DIR);
mkdirSync(XDG_CONFIG_HOME);
writeFileSync(SOUL_FILE, '# Soul\nYou are a helper.\n');

interface Run { stdout: string; stderr: string; status: number }

function run(args: string[], extraEnv: Record<string, string | undefined> = {}): Run {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 60000,
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      XDG_CONFIG_HOME,
      ...extraEnv,
    },
  });
  return {
    stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
    status: res.status ?? 1,
  };
}

function lineCount(s: string): number {
  return s.split('\n').filter((l) => l.length > 0).length;
}

describe('#741 -v after a subcommand name is that subcommand\'s --verbose', () => {
  it('dist/cli.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('secure -v <dir> --ci runs the scan with verbose output, not the version line', () => {
    if (!existsSync(CLI_PATH)) return;
    const short = run(['secure', '-v', EMPTY_DIR, '--ci']);
    const long = run(['secure', '--verbose', EMPTY_DIR, '--ci']);
    const plain = run(['secure', EMPTY_DIR, '--ci']);

    expect(short.stdout).not.toMatch(VERSION_LINE);
    expect(short.stderr).toMatch(/Scanning /);
    expect(short.status).toBe(long.status);
    // Verbose lists the passed checks too, so it prints more than the plain
    // scan. `-v` must land on the same output as the long spelling.
    expect(lineCount(short.stdout)).toBe(lineCount(long.stdout));
    expect(lineCount(short.stdout)).toBeGreaterThan(lineCount(plain.stdout));
  });

  it('scan-soul -v <file> runs the scan, not the version line', () => {
    if (!existsSync(CLI_PATH)) return;
    const short = run(['scan-soul', '-v', SOUL_FILE]);
    const long = run(['scan-soul', '--verbose', SOUL_FILE]);

    expect(short.stdout).not.toMatch(VERSION_LINE);
    expect(short.stdout).toMatch(/SOUL\.md/);
    expect(short.status).toBe(long.status);
    expect(lineCount(short.stdout)).toBe(lineCount(long.stdout));
  });

  it('check -v <dir> --offline reaches the check action, not the version line', () => {
    if (!existsSync(CLI_PATH)) return;
    const short = run(['check', '-v', EMPTY_DIR, '--offline']);
    const long = run(['check', '--verbose', EMPTY_DIR, '--offline']);

    expect(short.stdout).not.toMatch(VERSION_LINE);
    // The proof the action ran is the check's own output (a report, or the
    // not-measured banner on a build that withholds one for an empty tree);
    // the exit code is the check's contract, not this test's, so it is only
    // pinned equal between the two spellings.
    expect(short.stdout + short.stderr).toMatch(/NOT MEASURED|Security|\/100/);
    expect(short.status).toBe(long.status);
    expect(short.stdout).toBe(long.stdout);
  });

  it('wild registers the -v it cites in its own help', () => {
    if (!existsSync(CLI_PATH)) return;
    const help = run(['wild', '--help']);
    expect(help.status).toBe(0);
    expect(help.stdout).toMatch(/^\s+-v, --verbose\b/m);
  });

  it('--version and a bare -v still print the version line and exit 0', () => {
    if (!existsSync(CLI_PATH)) return;
    for (const flag of ['--version', '-v']) {
      const res = run([flag]);
      expect(res.status).toBe(0);
      const lines = res.stdout.trim().split('\n').filter((l) => l.length > 0);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatch(VERSION_LINE);
    }
  });

  it('--version after a subcommand name prints the version line and runs no scan', () => {
    if (!existsSync(CLI_PATH)) return;
    const res = run(['secure', '--version', EMPTY_DIR]);
    expect(res.status).toBe(0);
    const lines = res.stdout.trim().split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(VERSION_LINE);
    expect(res.stderr).not.toMatch(/Scanning /);
    expect(res.stderr).not.toMatch(/unknown option/);
  });

  it('-V means the version at the root and after a subcommand name', () => {
    if (!existsSync(CLI_PATH)) return;
    for (const args of [['-V'], ['check', '-V', EMPTY_DIR, '--offline']]) {
      const res = run(args);
      expect(res.status).toBe(0);
      const lines = res.stdout.trim().split('\n').filter((l) => l.length > 0);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatch(VERSION_LINE);
      expect(res.stderr).not.toMatch(/NOT MEASURED/);
    }
  });

  it('root --help lists -V beside -v, --version', () => {
    if (!existsSync(CLI_PATH)) return;
    const help = run(['--help']);
    expect(help.status).toBe(0);
    expect(help.stdout).toMatch(/^\s+-v, --version\b/m);
    expect(help.stdout).toMatch(/^\s+-V\b/m);
  });

  it('--version-id is not the version flag: secure --version-id x --help reaches secure', () => {
    if (!existsSync(CLI_PATH)) return;
    const res = run(['secure', '--version-id', 'x', '--help']);
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Usage: hackmyagent secure/);
    expect(res.stdout).not.toMatch(VERSION_LINE);
  });

  it('--no-color is still accepted before and after the subcommand name', () => {
    if (!existsSync(CLI_PATH)) return;
    // Unset NO_COLOR so the flag is the only thing asking for plain output.
    const after = run(['secure', EMPTY_DIR, '--ci', '--no-color'], { NO_COLOR: undefined });
    const before = run(['--no-color', 'secure', EMPTY_DIR, '--ci'], { NO_COLOR: undefined });
    for (const res of [after, before]) {
      expect(res.stderr).not.toMatch(/unknown option/);
      expect(res.stderr).toMatch(/Scanning /);
      expect(res.status).toBe(0);
    }
  });
});
