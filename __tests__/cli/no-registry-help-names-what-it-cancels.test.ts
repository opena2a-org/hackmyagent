/**
 * #987 — `secure --help` and `attack --help` describe `--no-registry` by what
 * it cancels.
 *
 * Before: both printed `--no-registry  Skip auto-publishing results to OpenA2A
 * Registry`. Neither command publishes by default: a result reaches the
 * Registry only when a flag asks for it, and on these two commands
 * `--no-registry` cancels exactly one of those flags, `--publish`. "Auto-
 * publishing" told a reader there was a default upload to turn off.
 *
 * RED-ON-BASE cells fail on the help text before the fix; the PIN cell holds
 * the behaviour the new text describes and passes on both.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC_CLI = path.join(REPO_ROOT, 'src', 'cli.ts');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

beforeAll(assertDistFreshIfPresent);

/** The built CLI when present, `tsx` over `src/` otherwise — never a skip. */
function cliCommand(args: string[]): { bin: string; argv: string[] } {
  if (fs.existsSync(BUILT_CLI)) return { bin: process.execPath, argv: [BUILT_CLI, ...args] };
  if (!fs.existsSync(TSX)) {
    throw new Error('Neither dist/cli.js nor node_modules/.bin/tsx is present; run `npm ci` before this suite.');
  }
  return { bin: TSX, argv: [SRC_CLI, ...args] };
}

function cliEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-987-home-') };
  delete env.HMA_CLI_PREFIX;
  return env;
}

/** The description Commander prints for `--no-registry`, continuation lines joined. */
function noRegistryHelp(command: 'secure' | 'attack'): string {
  const { bin, argv } = cliCommand([command, '--help']);
  // eslint-disable-next-line no-control-regex
  const help = execFileSync(bin, argv, { env: cliEnv(), encoding: 'utf8', cwd: REPO_ROOT }).replace(/\x1b\[[0-9;]*m/g, '');
  const lines = help.split('\n');
  const start = lines.findIndex((l) => /^\s+--no-registry\s/.test(l));
  expect(start, `${command} --help lists --no-registry`).toBeGreaterThanOrEqual(0);
  const parts = [lines[start].replace(/^\s+--no-registry\s+/, '')];
  for (let i = start + 1; i < lines.length && /^\s{10,}[^\s-]/.test(lines[i]); i++) {
    parts.push(lines[i].trim());
  }
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

describe('#987 --no-registry help names what it cancels', { timeout: 120_000 }, () => {
  for (const command of ['secure', 'attack'] as const) {
    it(`RED-ON-BASE: ${command} --help does not describe a default upload`, () => {
      const text = noRegistryHelp(command);
      expect(text).not.toMatch(/auto-?publish/i);
      expect(text).toContain('--publish');
    });
  }

  it('PIN: secure --publish --no-registry publishes nothing and says so', () => {
    const dir = tempDir('hma-987-');
    fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx987", "version": "1.0.0", "private": true }\n');
    fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = () => 1;\n');
    try {
      const { bin, argv } = cliCommand([
        'secure', dir, '--publish', '--no-registry',
        // Nothing listens here: if the cancel ever stopped holding, the attempt
        // fails locally rather than reaching a service.
        '--registry-url', 'http://localhost:9',
        '--scan-depth', 'quick', '--static-only', '--no-machine-posture', '--no-contribute',
      ]);
      const r = spawnSync(bin, argv, { env: cliEnv(), encoding: 'utf8', cwd: REPO_ROOT, timeout: 110_000, maxBuffer: 64 * 1024 * 1024 });
      expect(r.stdout).toContain('Publish skipped: --no-registry flag is active.');
      expect(r.stdout + r.stderr).not.toMatch(/Publishing results|Published to|Failed to publish/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
