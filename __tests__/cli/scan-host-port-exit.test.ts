/**
 * `scan <host>:<port>` scans the port it names, and a target the scan did not
 * test never exits 0.
 *
 * Before: `scan 127.0.0.1:PORT` against a port that accepted the connection
 * and answered no HTTP request printed "Score: 100/100" and "No security
 * issues found!" and exited 0; a closed or unreachable target printed its
 * status finding (MEDIUM or LOW) and exited 0 as well, so a CI job reading
 * the exit code passed a target nothing had examined.
 *
 * Now: an answering host:port is scanned on that port and exits 0 when clean;
 * an unreachable target, a target with no open port, and an open port that
 * answered nothing exit 2, the code of an incomplete run, in text and JSON.
 *
 * The CLI is spawned asynchronously: the servers live in this process, and
 * `spawnSync` would block the event loop they need to answer.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import type { AddressInfo } from 'node:net';
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

function run(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const { bin, argv } = cliCommand(args);
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    HOME: tempDir('hma-scan-host-port-home-'),
  };
  delete env.HMA_CLI_PREFIX;
  return new Promise((resolve, reject) => {
    const child = spawn(bin, argv, { env, cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += String(d); });
    child.stderr.on('data', (d) => { stderr += String(d); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

let answering: http.Server;
let answeringPort: number;
let silent: net.Server;
let silentPort: number;
const held: net.Socket[] = [];
let closedPort: number;

beforeAll(async () => {
  answering = http.createServer((_req, res) => { res.writeHead(404); res.end('not found'); });
  await new Promise<void>((resolve) => answering.listen(0, '127.0.0.1', resolve));
  answeringPort = (answering.address() as AddressInfo).port;

  // Accepts the connection and never writes a byte.
  silent = net.createServer((socket) => { held.push(socket); });
  await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
  silentPort = (silent.address() as AddressInfo).port;

  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  closedPort = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
});

afterAll(async () => {
  for (const s of held) s.destroy();
  await new Promise<void>((resolve) => answering.close(() => resolve()));
  await new Promise<void>((resolve) => silent.close(() => resolve()));
});

describe('scan <host>:<port>', () => {
  it('scans the named port of an answering server and exits 0 when clean', async () => {
    const r = await run(['scan', `127.0.0.1:${answeringPort}`, '-t', '1000']);

    expect(r.stdout).toContain('(1 port,');
    expect(r.stdout).toContain(`Open Ports: ${answeringPort}`);
    expect(r.stdout).toContain('No security issues found');
    expect(r.code, r.stdout + r.stderr).toBe(0);
  }, 60_000);

  it('an open port that answers no HTTP request is reported untested and exits 2', async () => {
    const r = await run(['scan', `127.0.0.1:${silentPort}`, '-t', '300']);

    expect(r.stdout).toContain(`Open Ports: ${silentPort}`);
    expect(r.stdout).toContain('SCAN-NO-ANSWER');
    expect(r.stdout).not.toContain('No security issues found');
    expect(r.code, r.stdout + r.stderr).toBe(2);
  }, 60_000);

  it('a port nothing listens on exits 2', async () => {
    const r = await run(['scan', `127.0.0.1:${closedPort}`, '-t', '1000']);

    expect(r.stdout).toContain(String(closedPort));
    expect(r.stdout).toContain('SCAN-NO-OPEN-PORTS');
    expect(r.code, r.stdout + r.stderr).toBe(2);
  }, 60_000);

  it('a name that does not resolve exits 2', async () => {
    const r = await run(['scan', 'scan-host-port.invalid:8080', '-t', '1000']);

    expect(r.stdout).toContain('SCAN-UNREACHABLE');
    expect(r.code, r.stdout + r.stderr).toBe(2);
  }, 60_000);

  it('--json exits 2 on the same untested target, with the body naming the port', async () => {
    const r = await run(['scan', `127.0.0.1:${silentPort}`, '-t', '300', '--json']);

    const body = JSON.parse(r.stdout.slice(r.stdout.indexOf('{'))) as {
      unansweredPorts?: number[];
      findings: { checkId: string }[];
    };
    expect(body.unansweredPorts).toEqual([silentPort]);
    expect(body.findings.map((f) => f.checkId)).toContain('SCAN-NO-ANSWER');
    expect(r.code, r.stdout + r.stderr).toBe(2);
  }, 60_000);
});
