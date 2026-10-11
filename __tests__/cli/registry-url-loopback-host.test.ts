/**
 * A registry URL must use https, except plain http to this machine for local
 * development: `localhost`, `127.0.0.1` or `[::1]`, judged by the host the
 * URL parser reads. Before this, the check was a string prefix,
 * `startsWith('http://localhost')`, so `http://localhost.example.com` and
 * `http://localhost@example.com` passed it, and `secure --ci-publish` sent its
 * scan result over plain http to a remote host.
 *
 * The registry URL is checked when the CLI starts, so a refused value ends any
 * command with exit 1 before it does any work, and an accepted one lets
 * `--version` run. Hermetic: no cell reaches a registry; the CLI runs with
 * __tests__/helpers/loopback-only.cjs preloaded, so a connection to any host
 * but loopback is refused before it is made.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');
const REFUSAL = 'Error: Registry URL must use HTTPS.';

function runCli(args: string[], registryUrl: string) {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY', 'ANTHROPIC_API_KEY']) {
    delete env[name];
  }
  const home = tempDir('hma-registry-url-home-');
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: path.join(home, '.opena2a'),
      REGISTRY_URL: registryUrl,
      CI_SCAN_HMAC_SECRET: 'fake-test-secret',
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('registry URL: a remote host whose name starts with "localhost" is not taken for this machine', () => {
  for (const registryUrl of [
    'http://localhost.example.com',
    'http://localhost.example.com:8080/api',
    'http://localhost@example.com',
    'http://localhostx:8080',
    'http://example.com',
  ]) {
    it(`secure --ci-publish refuses ${registryUrl} before it scans`, () => {
      const project = tempDir('hma-registry-url-project-');
      fs.writeFileSync(path.join(project, 'package.json'), '{"name":"example-repo","version":"1.0.0"}\n');
      const run = runCli(['secure', project, '--no-machine-posture', '--ci-publish'], registryUrl);
      expect(run.status, `stdout:\n${run.stdout}\nstderr:\n${run.stderr}`).toBe(1);
      expect(run.stderr).toContain(REFUSAL);
      expect(run.stderr).toContain('Only https:// URLs and http://localhost, http://127.0.0.1 and http://[::1] are allowed.');
      expect(run.stdout + run.stderr).not.toContain('CI scan result');
    });
  }
});

describe('registry URL: https, and plain http to this machine, are accepted', () => {
  for (const registryUrl of [
    'https://registry.example',
    'http://localhost:9',
    'http://localhost',
    'http://127.0.0.1:9',
    'http://[::1]:9',
  ]) {
    it(`accepts ${registryUrl}`, () => {
      const run = runCli(['--version'], registryUrl);
      expect(run.status, `stdout:\n${run.stdout}\nstderr:\n${run.stderr}`).toBe(0);
      expect(run.stderr).not.toContain(REFUSAL);
    });
  }
});
