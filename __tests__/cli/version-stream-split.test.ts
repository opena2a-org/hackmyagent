/**
 * cli-ui 0.5.2 — `--version` stream split.
 *
 * The version output is rendered via `versionLineParts` and a manual
 * `option:version` handler (not Commander's `.version()`, which writes
 * everything to stdout). The bare `hackmyagent x.y.z` must land on stdout as
 * a single parseable line; the telemetry disclosure must land on stderr.
 *
 * A script doing `hackmyagent --version` (capturing stdout) must get exactly
 * one clean line, with the privacy disclosure still surfaced via stderr.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function runVersion(flag: string): { stdout: string; stderr: string; status: number } {
  const res = spawnSync(process.execPath, [CLI_PATH, flag], {
    encoding: 'utf8',
    timeout: 20000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'on' },
  });
  return {
    stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
    status: res.status ?? 1,
  };
}

describe('--version stream split (cli-ui 0.5.2)', () => {
  it('dist/cli.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('stdout is a single clean `hackmyagent x.y.z` line, telemetry goes to stderr', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, stderr, status } = runVersion('--version');
    expect(status).toBe(0);

    const stdoutLines = stdout.trim().split('\n').filter((l) => l.length > 0);
    expect(stdoutLines).toHaveLength(1);
    expect(stdoutLines[0]).toMatch(/^hackmyagent \d+\.\d+\.\d+/);
    // The telemetry disclosure must NOT pollute the parseable stream.
    expect(stdout).not.toMatch(/Telemetry:/);

    // Disclosure still surfaces — on stderr.
    expect(stderr).toMatch(/Telemetry: on/);
  });

  it('-v behaves identically to --version (stdout, stderr disclosure, exit 0)', () => {
    if (!existsSync(CLI_PATH)) return;
    const long = runVersion('--version');
    const short = runVersion('-v');
    expect(short.status).toBe(0);
    expect(short.stdout.trim()).toBe(long.stdout.trim());
    // The disclosure must also surface on stderr via the short flag.
    expect(short.stderr).toMatch(/Telemetry: on/);
  });

  it('OPENA2A_TELEMETRY=off: stdout stays the single version line, no telemetry leak', () => {
    if (!existsSync(CLI_PATH)) return;
    const res = spawnSync(process.execPath, [CLI_PATH, '--version'], {
      encoding: 'utf8',
      timeout: 20000,
      env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' },
    });
    const stdout = (res.stdout ?? '').replace(STRIP_ANSI, '');
    expect(res.status).toBe(0);
    const lines = stdout.trim().split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^hackmyagent \d+\.\d+\.\d+/);
    expect(stdout).not.toMatch(/Telemetry:/);
  });
});
