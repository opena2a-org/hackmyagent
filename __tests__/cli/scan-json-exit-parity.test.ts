/**
 * #445 — `scan` and `scan --json` exit the same way on the same run.
 *
 * `scan --help` documents "Exit code 1 if critical/high issues found". The text
 * channel honoured it; the JSON channel wrote its body and returned before the
 * check, so it exited 0 while that body listed criticals. A CI job piping the
 * JSON never failed. Measured on `044301c5` against a local server answering
 * 200 with a JSON body on every path: `scan` exit 1, `scan --json` exit 0.
 *
 * The CLI is spawned asynchronously: the server lives in this process, and
 * `spawnSync` would block the event loop it needs to answer.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"id":"x"}');
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
        HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += String(d); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout }));
  });
}

describe('#445 scan exit code does not depend on the output channel', () => {
  it('text and --json both exit 1 when the report holds a critical or high finding', async () => {
    const text = await run(['scan', '127.0.0.1', '-p', String(port)]);
    const json = await run(['scan', '127.0.0.1', '-p', String(port), '--json']);

    // Non-vacuity: the JSON body itself must carry a critical or high finding,
    // or an exit of 1 would be asserting a failure the report does not state.
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{'))) as { findings: { severity: string }[] };
    const failing = body.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    expect(failing.length, `no critical/high finding against the local server:\n${json.stdout}`).toBeGreaterThan(0);

    expect(text.code, 'scan (text) exit code').toBe(1);
    expect(json.code, 'scan --json exited differently from scan on the same run').toBe(text.code);
  });
});
