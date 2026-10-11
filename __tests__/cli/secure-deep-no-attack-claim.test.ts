/**
 * #975 — `secure --deep` advertised "adaptive attacks" that never run.
 *
 * Measured: `secure --help` described `--deep` as "static + semantic +
 * behavioral simulation + adaptive attacks", and with the analyst daemon
 * reachable the text banner printed the same. `--deep` runs Layer 3 analysis
 * and the behavioral simulation; no attack engine is called on that path. Both
 * surfaces now name only what runs.
 *
 * The banner is only printed when the daemon answers `/health`, so the suite
 * stands up a local server that answers it and points `NANOMIND_URL` at it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC_CLI = path.join(REPO_ROOT, 'src', 'cli.ts');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

/** Any wording that tells the reader an attack stage runs. */
const ATTACK_CLAIM = /adaptive|attack/i;

beforeAll(assertDistFreshIfPresent);

function cliInvocation(args: string[]): { bin: string; argv: string[] } {
  if (existsSync(BUILT_CLI)) return { bin: process.execPath, argv: [BUILT_CLI, ...args] };
  if (!existsSync(TSX)) {
    throw new Error('Neither dist/cli.js nor node_modules/.bin/tsx is present; run `npm ci` before this suite.');
  }
  return { bin: TSX, argv: [SRC_CLI, ...args] };
}

function baseEnv(): NodeJS.ProcessEnv {
  const { ANTHROPIC_API_KEY: _key, NODE_OPTIONS: _opts, HMA_CLI_PREFIX: _prefix, ...env } = process.env;
  return env;
}

// eslint-disable-next-line no-control-regex
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

describe('#975: secure --deep names only the stages it runs', () => {
  it('secure --help describes --deep without claiming an attack stage', () => {
    const { bin, argv } = cliInvocation(['secure', '--help']);
    const help = stripAnsi(execFileSync(bin, argv, { env: baseEnv(), encoding: 'utf8', cwd: REPO_ROOT }));
    const lines = help.split('\n');
    const at = lines.findIndex((l) => /^\s*--deep\s/.test(l));
    expect(at, 'secure --help no longer lists --deep').toBeGreaterThanOrEqual(0);
    // The description wraps; read the option line and its indented continuation lines.
    const parts = [lines[at]];
    for (let i = at + 1; i < lines.length && /^\s{20,}\S/.test(lines[i]); i++) parts.push(lines[i]);
    const block = parts.join(' ');
    expect(block).toMatch(/behavioral\s+simulation/);
    expect(block).not.toMatch(ATTACK_CLAIM);
  });

  it('the --deep banner printed with the analyst daemon reachable claims no attack stage', async () => {
    const server: Server = createServer((req, res) => {
      res.statusCode = req.url === '/health' ? 200 : 404;
      res.end('{}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const dir = tempDir('hma-975-');
    writeFileSync(path.join(dir, 'config.json'), '{\n  "service": "billing"\n}\n');
    try {
      const { port } = server.address() as AddressInfo;
      const { bin, argv } = cliInvocation(['secure', dir, '--deep']);
      // Spawned asynchronously: the stub daemon answers from this process's
      // event loop, which a synchronous spawn would block.
      const stdout = await new Promise<string>((resolve, reject) => {
        const child = spawn(bin, argv, {
          cwd: dir,
          env: { ...baseEnv(), NANOMIND_URL: `http://127.0.0.1:${port}` },
        });
        let out = '';
        child.stdout.on('data', (d) => { out += d; });
        child.on('error', reject);
        child.on('close', () => resolve(stripAnsi(out)));
      });
      const banner = stdout.split('\n').find((l) => l.startsWith('Analysis:'));
      expect(banner, `no "Analysis:" banner in output:\n${stdout.slice(0, 2000)}`).toBeDefined();
      expect(banner).toMatch(/behavioral simulation/);
      expect(banner).not.toMatch(ATTACK_CLAIM);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 120_000);
});
