// Regression tests for `check <npm-name> --no-scan --json` when the Registry
// query FAILS (timeout, 5xx, network). A genuine not-found is deliberately
// out of scope here: its behaviour is unchanged and pinned elsewhere
// (check-not-found-json.test.ts F3; the parity fixture check-not-found).
//
// Background: `checkNpmPackage` honored `--no-scan` only when the Registry
// query returned a record. When `queryRegistry` returned null — which it did
// for a timeout, a 5xx, a network error AND a genuine 404 alike — the
// `registryData?.found` guard was skipped and control fell through to
// "Download and scan". In `--json` mode nothing was printed about it, so a
// machine consumer received a valid scan document with exit 0 in place of
// the registry record it asked for. The parity gate (opena2a-parity,
// fixture check-registered-ai) measured exactly that on an unchanged base:
// four registry keys absent, exit 0, and its transient-probe retry, keyed
// on a non-zero exit, could not see it.
//
// Two layers, matching check-not-found-json.test.ts:
//
// 1. Deterministic lock-in over src/cli.ts: the npm --no-scan branch
//    distinguishes a registry ERROR from a registry miss and returns on the
//    error before the scan, and the registry timeout is the same number
//    ai-trust uses for the same question against the same client.
//
// 2. Spawned cells against a LOCAL fake Registry (REGISTRY_URL honored, no
//    network): a 503 exits non-zero with a body that names the error and no
//    scan document; a 200 record exits 0 with source: registry.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI_TS = join(REPO_ROOT, 'src', 'cli.ts');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
// A name no registry carries, so a fall-through to `npm pack` cannot succeed
// by accident and a scan document in the output is unambiguous.
const PKG = '@opena2a-parity/does-not-exist-9308';

function canRunSpawn(): boolean {
  return existsSync(CLI);
}

function npmNoScanBranch(source: string): string {
  const start = source.indexOf('async function checkNpmPackage(');
  expect(start).toBeGreaterThan(-1);
  const end = source.indexOf('// Download and scan', start);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe('check <npm-name> --no-scan: lock-in over src/cli.ts', () => {
  const source = readFileSync(CLI_TS, 'utf8');

  it('the npm --no-scan branch treats a registry ERROR as its own case, named registry-unreachable', () => {
    const branch = npmNoScanBranch(source);
    expect(branch).toContain("status === 'error'");
    expect(branch).toContain("errorClass: 'registry-unreachable'");
  });

  it('the registry ERROR case returns before "Download and scan", through the shared emitter', () => {
    const branch = npmNoScanBranch(source);
    const errCase = branch.slice(branch.indexOf("status === 'error'"));
    const emit = errCase.indexOf('emitRegistryQueryError(');
    expect(emit).toBeGreaterThan(-1);
    expect(errCase.slice(emit, emit + 200)).toMatch(/emitRegistryQueryError\([^\n]*\);[^\n]*\n\s*return;/);
  });

  it('the shared emitter writes the diagnostic on stderr in EVERY mode and exits unmeasured', () => {
    const start = source.indexOf('function emitRegistryQueryError(');
    expect(start).toBeGreaterThan(-1);
    const body = source.slice(start, source.indexOf('\n}\n', start));
    expect(body).toContain('console.error(');
    expect(body).not.toContain('!options.json');
    expect(body).not.toContain('globalCiMode');
    expect(body).toContain("errorClass: 'registry-unreachable'");
    expect(body).toContain('raiseExitCode(EXIT_UNMEASURED)');
  });

  it('all three --no-scan paths route a registry error through the shared emitter', () => {
    expect((source.match(/emitRegistryQueryError\(/g) ?? []).length).toBe(4); // definition + npm + github + pypi
  });

  it('queryRegistry distinguishes a PackageNotFoundError from a RegistryApiError', () => {
    const start = source.indexOf('async function queryRegistryResult(');
    expect(start).toBeGreaterThan(-1);
    const body = source.slice(start, start + 2500);
    expect(body).toContain('PackageNotFoundError');
    expect(body).toContain("status: 'error'");
    expect(body).not.toMatch(/catch\s*\{\s*return null;?\s*\}/);
  });

  it('the registry timeout is the same number ai-trust uses for the same client', () => {
    // ai-trust/src/utils/registry-client.ts: REGISTRY_TIMEOUT_MS = 15000. Both
    // CLIs ask the same trust/query through @opena2a/registry-client; a
    // different patience for the same question is what made one of them fail
    // on a transient the other survived.
    expect(source).toMatch(/const REGISTRY_QUERY_TIMEOUT_MS = 15000;/);
    expect(source).not.toMatch(/timeoutMs:\s*5000/);
  });

  it('REGISTRY_URL honors the environment on the check path, like the other commands', () => {
    expect(source).toMatch(/const REGISTRY_URL = process\.env\.REGISTRY_URL \|\| 'https:\/\/api\.oa2a\.org';/);
  });
});

type Mode = 'error' | 'not-found' | 'found' | 'hang';

describe('check <npm-name> --no-scan --json against a local fake Registry', () => {
  let server: Server;
  let server6: Server | null = null;
  let port = 0;
  let mode: Mode = 'error';
  let hits = 0;

  beforeAll(async () => {
    server = createServer((req, res) => {
      hits += 1;
      if (!(req.url ?? '').startsWith('/api/v1/trust/query')) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unexpected route', url: req.url }));
        return;
      }
      if (mode === 'hang') return; // never answers; the client's timeout decides
      if (mode === 'error') {
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream unavailable' }));
        return;
      }
      if (mode === 'not-found') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        packageId: '7b70f85f-0000-4000-8000-000000009308',
        name: PKG,
        trustScore: 91,
        trustLevel: 3,
        verdict: 'passed',
        scanStatus: 'warnings',
        packageType: 'mcp_server',
      }));
    });
    // The CLI accepts plain http only for `localhost`, and the client resolves
    // that name to whichever loopback family the OS lists first, so listen on
    // BOTH families at one port.
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
    server6 = createServer(server.listeners('request')[0] as Parameters<typeof createServer>[0]);
    await new Promise<void>((resolve) => {
      server6!.once('error', () => { server6 = null; resolve(); }); // no IPv6 loopback here: fine
      server6!.listen(port, '::1', resolve);
    });
    // Self-check: the test process itself can reach the listener by the name
    // the CLI will use. If this fails the harness is wrong, not the CLI.
    const probe = await fetch(`http://localhost:${port}/api/v1/trust/query?name=probe`);
    expect(probe.status).toBe(503);
    hits = 0;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (server6) await new Promise<void>((resolve) => server6!.close(() => resolve()));
  });

  // The CLI is spawned ASYNCHRONOUSLY and awaited: the fake Registry lives in
  // this process, and a synchronous spawn would block the event loop for the
  // child's whole lifetime, so the listener could never accept the request
  // (measured: 15 s client timeout, zero hits, even with a second listener
  // per address family). A minimal environment keeps an inherited proxy
  // setting from carrying the loopback request elsewhere.
  function run(target: string = PKG): Promise<{ status: number | null; json: Record<string, unknown> | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, 'check', target, '--no-scan', '--json', '--ci'], {
        env: {
          PATH: process.env.PATH ?? '',
          HOME: process.env.HOME ?? '',
          TMPDIR: process.env.TMPDIR ?? '',
          REGISTRY_URL: `http://localhost:${port}`,
          HMA_TELEMETRY: '0',
          NO_COLOR: '1',
          NO_PROXY: 'localhost,127.0.0.1,::1',
        },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += String(d); });
      child.stderr.on('data', (d) => { stderr += String(d); });
      const killer = setTimeout(() => child.kill('SIGKILL'), 60_000);
      child.on('close', (status) => {
        clearTimeout(killer);
        let json: Record<string, unknown> | null = null;
        try { json = JSON.parse(stdout); } catch { json = null; }
        resolve({ status, json, stdout, stderr });
      });
    });
  }

  it.skipIf(!canRunSpawn())('a Registry 503 under --no-scan exits non-zero with a body that names the error, and no scan document', async () => {
    mode = 'error'; hits = 0;
    const r = await run();
    expect(r.json, r.stdout + r.stderr).not.toBeNull();
    expect(r.status).not.toBe(0);
    expect(r.json?.source).toBe('registry');
    expect(r.json?.found).toBe(false);
    expect(r.json?.errorClass).toBe('registry-unreachable');
    expect(String(r.json?.error)).toMatch(/Registry/);
    expect(r.json?.type).not.toBe('npm-package');
    expect(r.json).not.toHaveProperty('score');
    expect(hits, `stderr: ${r.stderr.slice(0, 300)}`).toBe(1);
    // The diagnostic reaches the machine-readable path too: stderr says what happened.
    expect(r.stderr).toMatch(/Registry/);
  });

  // The same root cause on the other two callers of the query: a timeout or
  // 5xx used to be reported as `not found in the OpenA2A Registry`, a
  // definitive absence for a question that never completed. No clone, no
  // PyPI fetch: the fake Registry is the only thing these runs may touch.
  it.skipIf(!canRunSpawn())('GitHub path: a Registry 503 under --no-scan is an error, not a not-found', async () => {
    mode = 'error'; hits = 0;
    const r = await run('opena2a-parity/does-not-exist-9308');
    expect(r.json, r.stdout + r.stderr).not.toBeNull();
    expect(r.status).not.toBe(0);
    expect(r.json?.errorClass).toBe('registry-unreachable');
    expect(String(r.json?.error)).not.toMatch(/not found in the OpenA2A Registry/);
    expect(r.json).not.toHaveProperty('score');
    expect(hits).toBe(1);
  });

  it.skipIf(!canRunSpawn())('PyPI path: a Registry 503 under --no-scan is an error, not a not-found', async () => {
    mode = 'error'; hits = 0;
    const r = await run('pip:does-not-exist-9308');
    expect(r.json, r.stdout + r.stderr).not.toBeNull();
    expect(r.status).not.toBe(0);
    expect(r.json?.errorClass).toBe('registry-unreachable');
    expect(String(r.json?.error)).not.toMatch(/not found in the OpenA2A Registry/);
    expect(r.json).not.toHaveProperty('score');
    expect(hits).toBe(1);
  });

  it.skipIf(!canRunSpawn())('a Registry record under --no-scan exits 0 with source: registry', async () => {
    mode = 'found'; hits = 0;
    const r = await run();
    expect(r.json, r.stdout + r.stderr).not.toBeNull();
    expect(r.status).toBe(0);
    expect(r.json?.source).toBe('registry');
    expect(r.json?.trustLevel).toBe(3);
    expect(r.json?.packageType).toBe('mcp_server');
    expect(r.json?.verdict).toBe('passed');
    expect(hits).toBe(1);
  });
});
