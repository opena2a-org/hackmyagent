/**
 * #448 — an exposure finding carries a command that shows what the scan saw.
 *
 * The CONFIG-EXPOSED and CLAUDE-MD-EXPOSED findings had prose fixes and no
 * way to check them, so a user could not cheaply disprove a false one. Each
 * now names `curl -si <url>`, in `--verbose` text and in `--json`.
 *
 * The CLI is spawned asynchronously: the server lives in this process, and
 * `spawnSync` would block the event loop it needs to answer.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/.env') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('APP_MODE=production\n');
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function run(args: string[]): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: tempDir('hma-home-'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += String(d); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout }));
  });
}

describe('#448 scan exposure findings name a curl the user can run', () => {
  it('--json carries verify on the finding', async () => {
    const json = await run(['scan', '127.0.0.1', '-p', String(port), '--json']);
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{'))) as {
      findings: { checkId: string; path?: string; verify?: string }[];
    };
    const env = body.findings.find((f) => f.checkId === 'CONFIG-EXPOSED' && f.path === '/.env');
    expect(env, json.stdout).toBeDefined();
    expect(env!.verify).toBe(`curl -si http://127.0.0.1:${port}/.env`);
  });

  it('--verbose prints the Verify line under the finding', async () => {
    const text = await run(['scan', '127.0.0.1', '-p', String(port), '--verbose']);
    expect(text.stdout).toContain(`Verify: curl -si http://127.0.0.1:${port}/.env`);
  });
});
