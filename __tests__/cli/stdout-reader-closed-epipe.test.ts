/**
 * #961 — `check-metadata --json | head -5` printed `Error: EPIPE: broken
 * pipe, write` with a stack trace from `writeLargeStdout` and exited 1. The
 * reader closing its end of the pipe is how `head`, `grep -m1` and `jq` stop
 * early; it is not a failure of the command. The write stops there and the
 * command ends with the exit code it settles on (0 for check-metadata).
 *
 * Two shapes of the same close, both on the built CLI:
 * - `| head -5` after the first bytes, the reported command. It hits EPIPE
 *   only while the JSON is larger than what the pipe buffer and head's first
 *   read hold together (89,543 bytes against a 64KB pipe when reported).
 * - the reader closed before the first byte, which makes the first write
 *   fail with EPIPE whatever the output size or buffer size, so the
 *   regression is caught even if the document shrinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');
const HAS_BASH = process.platform !== 'win32' && spawnSync('bash', ['-c', 'true']).status === 0;

// Made outside a test, so the helper removes it when the file finishes.
let home: string;
beforeAll(() => {
  home = tempDir('hma-961-home-');
});

type Run = { code: number | null; signal: NodeJS.Signals | null; stderr: string };

function collect(child: ReturnType<typeof spawn>): Promise<Run> {
  return new Promise((resolve, reject) => {
    let stderr = '';
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (d: string) => {
      stderr += d;
    });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, stderr }));
  });
}

function childEnv(): NodeJS.ProcessEnv {
  return { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home };
}

describe.skipIf(!HAS_BASH || !existsSync(CLI))('stdout reader closing early (#961)', () => {
  it('check-metadata --json | head -5 exits 0 with no stack trace', async () => {
    // The exit status is the CLI's own (PIPESTATUS[0]), not head's.
    const child = spawn(
      'bash',
      ['-c', '"$0" "$1" check-metadata --json | head -5 >/dev/null; exit "${PIPESTATUS[0]}"', process.execPath, CLI],
      { stdio: ['ignore', 'ignore', 'pipe'], env: childEnv() },
    );
    const run = await collect(child);
    expect(run.stderr).not.toMatch(/EPIPE|broken pipe|\n\s+at /);
    expect(run.code).toBe(0);
  }, 60_000);

  it('check-metadata --json exits 0 with no stack trace when the reader closes before the first byte', async () => {
    const child = spawn(process.execPath, [CLI, 'check-metadata', '--json'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: childEnv(),
    });
    child.stdout!.destroy();
    const run = await collect(child);
    expect(run.stderr).not.toMatch(/EPIPE|broken pipe|\n\s+at /);
    expect(run.signal).toBeNull();
    expect(run.code).toBe(0);
  }, 60_000);
});
