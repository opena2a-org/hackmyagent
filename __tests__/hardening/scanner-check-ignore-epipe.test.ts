import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

const execFileAsync = promisify(execFile);

/**
 * Regression: git check-ignore stdin EPIPE must never become an uncaught
 * exception (v0.25.0 release workflow failure, 3x "write EPIPE" from
 * scanner.ts gitCommittable).
 *
 * `child.stdin.end(payload)` errors ASYNCHRONOUSLY when the child exits
 * before draining the pipe — the surrounding try/catch only covers a
 * synchronous throw, so without an 'error' listener on stdin the EPIPE is
 * an uncaught exception that crashes the whole process (a user's `secure`
 * run, or the CI test runner).
 *
 * Deterministic reproduction: a fake `git` on PATH exits 128 immediately
 * without reading stdin, and the path payload exceeds the 64KB pipe buffer
 * so the queued remainder is guaranteed to hit the closed pipe. The
 * scenario runs in a SUBPROCESS so an uncaught exception is observable as
 * a non-zero exit instead of poisoning the vitest worker.
 */
describe('gitCommittable stdin EPIPE resilience', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-epipe-'));
  });
  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('survives git exiting before stdin drains (>64KB payload) and falls back conservatively (null)', async () => {
    const shimDir = path.join(tempDir, 'bin');
    const targetDir = path.join(tempDir, 'target');
    await fs.mkdir(shimDir, { recursive: true });
    await fs.mkdir(targetDir, { recursive: true });

    // Fake git: exits "not a repo" instantly, never reads stdin.
    const shim = path.join(shimDir, 'git');
    await fs.writeFile(shim, '#!/bin/sh\nexit 128\n');
    await fs.chmod(shim, 0o755);

    // Runner executes in its own process; tsx resolves the TS import.
    // CJS runner (repo has no "type":"module"); the uncaught EPIPE is an
    // 'error' EVENT on a listener-less stream, so it crashes the subprocess
    // regardless of this IIFE's own rejection handling.
    const runner = path.join(tempDir, 'runner.ts');
    const scannerModule = path
      .resolve(__dirname, '../../src/hardening/scanner.ts')
      .split(path.sep)
      .join('/');
    await fs.writeFile(
      runner,
      [
        `import { HardeningScanner } from '${scannerModule}';`,
        `(async () => {`,
        `  const scanner: any = new HardeningScanner();`,
        // ~4000 paths x ~45 chars ≈ 180KB — well past the 64KB pipe buffer,
        // so the queued write MUST land on the closed pipe (EPIPE).
        `  const relPaths = Array.from({ length: 4000 }, (_, i) => 'certs/deeply/nested-' + i + '/service-key-' + i + '.pem');`,
        `  const result = await scanner.gitCommittable(process.argv[2], relPaths);`,
        `  console.log('RESULT:' + (result === null ? 'null' : 'array:' + result.length));`,
        `})().catch((e) => { console.error(e); process.exit(2); });`,
      ].join('\n'),
    );

    const tsxBin = path.resolve(__dirname, '../../node_modules/.bin/tsx');
    const { stdout } = await execFileAsync(tsxBin, [runner, targetDir], {
      env: { ...process.env, PATH: `${shimDir}${path.delimiter}${process.env.PATH ?? ''}` },
      timeout: 30000,
    });

    // exit 128 → gitCommittable resolves null → caller falls back to the
    // conservative text heuristic. An uncaught EPIPE instead rejects
    // execFileAsync with a non-zero subprocess exit and fails this test.
    expect(stdout).toContain('RESULT:null');
  }, 40000);
});
