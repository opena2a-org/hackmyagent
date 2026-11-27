// `check <name> --no-scan` reads the Registry's answer and nothing else, so the
// answer alone has to decide what the run says and how it exits.
//
// Five cases, each against a LOCAL fake Registry (REGISTRY_URL honored) and a
// LOCAL fake npm registry (npm_config_registry), both counting what reaches
// them:
//
//   - a Blocked record exits non-zero and says "Blocked". On the base it
//     exited 0: --no-scan printed the record and set no exit code at all;
//   - a 429 with `Retry-After: 30` is "could not ask", not "not found": the
//     JSON carries no `found: false`, a rate-limit error class and the wait,
//     and the text names the wait. On the base it was `found: false`,
//     `errorClass: registry-unreachable` and no wait;
//   - an answer whose package id is all zeros is the not-found block with no
//     level. On the base the id was truthy, so it rendered as a record;
//   - an answer with no trust level reads "unknown" and never "Blocked". On the
//     base a missing level defaulted to 0, which is Blocked;
//   - an npm name the Registry does not know, under --no-scan, sends nothing to
//     the npm registry and scans nothing. On the base it ran `npm pack`.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { assertDistFresh, assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const PKG = 'opena2a-answer-fixture-9411';

type Answer = { status: number; headers?: Record<string, string>; body: unknown };

const record = (over: Record<string, unknown>): Answer => ({
  status: 200,
  body: {
    packageId: '7b70f85f-0000-4000-8000-000000009411',
    name: PKG,
    trustScore: 0.5,
    verdict: 'passed',
    scanStatus: 'completed',
    packageType: 'mcp_server',
    ...over,
  },
});

/** A loopback listener on both address families at one port, counting requests. */
async function listen(handler: (url: string) => Answer): Promise<{ url: string; hits: string[]; close: () => Promise<void> }> {
  const hits: string[] = [];
  const onRequest = (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    hits.push(req.url ?? '');
    const a = handler(req.url ?? '');
    res.writeHead(a.status, { 'content-type': 'application/json', ...(a.headers ?? {}) });
    res.end(JSON.stringify(a.body));
  };
  const v4: Server = createServer(onRequest);
  await new Promise<void>((resolve) => v4.listen(0, '127.0.0.1', resolve));
  const addr = v4.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  let v6: Server | null = createServer(onRequest);
  await new Promise<void>((resolve) => {
    v6!.once('error', () => { v6 = null; resolve(); });
    v6!.listen(port, '::1', resolve);
  });
  return {
    url: `http://localhost:${port}`,
    hits,
    close: async () => {
      await new Promise<void>((resolve) => v4.close(() => resolve()));
      if (v6) await new Promise<void>((resolve) => v6!.close(() => resolve()));
    },
  };
}

let answer: Answer = record({ trustLevel: 3 });
let registry: Awaited<ReturnType<typeof listen>>;
let npmRegistry: Awaited<ReturnType<typeof listen>>;

beforeAll(async () => {
  registry = await listen((url) => (url.startsWith('/api/v1/trust/query') ? answer : { status: 404, body: { error: 'unexpected route' } }));
  npmRegistry = await listen(() => ({ status: 404, body: { error: 'Not found' } }));
});

// After the listeners start, so the afterAll below always has them to close.
beforeAll(assertDistFresh);

afterAll(async () => {
  await registry?.close();
  await npmRegistry?.close();
});

// Spawned asynchronously: the fake servers live in this process, and a
// synchronous spawn would block the event loop for the child's whole life.
function run(args: string[]): Promise<{ status: number | null; stdout: string; stderr: string; json: Record<string, unknown> | null }> {
  registry.hits.length = 0;
  npmRegistry.hits.length = 0;
  const npmCache = tempDir('hma-npm-cache-');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, 'check', ...args, '--no-scan', '--ci'], {
      env: {
        PATH: process.env.PATH ?? '',
        HOME: process.env.HOME ?? '',
        TMPDIR: process.env.TMPDIR ?? '',
        REGISTRY_URL: registry.url,
        npm_config_registry: `${npmRegistry.url}/`,
        npm_config_cache: npmCache,
        // This object replaces the worker's environment: usage telemetry off,
        // and its endpoint pinned to a discard port.
        OPENA2A_TELEMETRY: 'off',
        OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9',
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
      resolve({ status, stdout, stderr, json });
    });
  });
}

describe('check --no-scan: the Registry answer decides the output and the exit code', { timeout: 90_000 }, () => {
  it('a Blocked answer exits non-zero and says Blocked, in text and in JSON', async () => {
    answer = record({ trustLevel: 0, verdict: 'blocked' });
    const text = await run([PKG]);
    expect(text.status, text.stdout + text.stderr).not.toBe(0);
    expect(text.status).not.toBeNull();
    expect(text.stdout + text.stderr).toContain('Blocked');
    expect(text.stdout).toContain('Blocked (0 of 4)');

    const json = await run([PKG, '--json']);
    expect(json.status, json.stdout + json.stderr).not.toBe(0);
    expect(json.json?.trustLevel).toBe(0);
    expect(json.json?.trustLevelName).toBe('blocked');
    expect(registry.hits.length).toBe(1);
    expect(npmRegistry.hits).toEqual([]);
  });

  it('a Warning answer exits non-zero too; a Scanned one exits 0', async () => {
    answer = record({ trustLevel: 1, verdict: 'warning' });
    const warn = await run([PKG]);
    expect(warn.status, warn.stdout + warn.stderr).toBe(1);
    expect(warn.stdout).toContain('Warning (1 of 4)');

    answer = record({ trustLevel: 3 });
    const ok = await run([PKG]);
    expect(ok.status, ok.stdout + ok.stderr).toBe(0);
    expect(ok.stdout).toContain('Scanned (3 of 4)');
  });

  it('a 429 with Retry-After: 30 is "could not ask": no found:false, a rate-limit class, the wait in JSON and in text', async () => {
    answer = { status: 429, headers: { 'Retry-After': '30' }, body: { error: 'Too Many Requests' } };
    const json = await run([PKG, '--json']);
    expect(json.json, json.stdout + json.stderr).not.toBeNull();
    expect(json.status).toBe(2);
    expect(json.json).not.toHaveProperty('found');
    expect(json.json?.state).toBe('registry-error');
    expect(json.json?.errorClass).toBe('registry-rate-limited');
    expect(json.json?.registryError).toBe('rate-limited');
    expect(json.json?.retryAfterSeconds).toBe(30);
    expect(json.json?.statusCode).toBe(429);
    expect(json.stdout).not.toMatch(/"found":\s*false/);

    const text = await run([PKG]);
    expect(text.status).toBe(2);
    expect(text.stderr).toMatch(/Could not get an answer from the registry .*rate limited, try again in 30 s\./);
    expect(text.stderr).toContain('This is not a verdict.');
    expect(text.stdout + text.stderr).not.toMatch(/not found/i);
    expect(npmRegistry.hits).toEqual([]);
  });

  it('an answer whose package id is all zeros is the not-found block, with no level', async () => {
    answer = record({ packageId: '00000000-0000-0000-0000-000000000000', trustLevel: 3 });
    const text = await run([PKG]);
    expect(text.status, text.stdout + text.stderr).toBe(2);
    const out = text.stdout + text.stderr;
    expect(out).toMatch(/not found/i);
    expect(out).not.toMatch(/Blocked|Warning|Listed|Scanned|Verified/);
    expect(out).not.toMatch(/\bLevel\b/);

    const json = await run([PKG, '--json']);
    expect(json.json?.found).toBe(false);
    expect(json.json).not.toHaveProperty('trustLevel');
    expect(npmRegistry.hits).toEqual([]);
  });

  it('an answer with no trust level reads "unknown" and never "Blocked"', async () => {
    answer = record({ trustLevel: undefined });
    const text = await run([PKG]);
    const out = text.stdout + text.stderr;
    expect(out).toContain('unknown');
    expect(out).not.toContain('Blocked');
    expect(text.status).not.toBe(0);

    const json = await run([PKG, '--json']);
    expect(json.json?.trustLevel ?? null).toBeNull();
    expect(json.json?.trustLevelName).toBe('unknown');

    // Off the scale reads the same way.
    answer = record({ trustLevel: 7 });
    const off = await run([PKG]);
    expect(off.stdout + off.stderr).toContain('unknown');
    expect(off.stdout + off.stderr).not.toContain('Blocked');
  });

  it('an npm name the Registry does not know: no request to the npm registry, no scan, the not-found block', async () => {
    answer = { status: 404, body: { error: 'not found' } };
    const text = await run([PKG]);
    expect(registry.hits.length).toBe(1);
    expect(npmRegistry.hits, 'requests that reached the npm registry').toEqual([]);
    expect(text.status, text.stdout + text.stderr).toBe(2);
    expect(text.stderr).not.toContain('Downloading');
    expect(text.stderr).toContain(`Verify the URL: https://www.npmjs.com/package/${PKG}`);

    const json = await run([PKG, '--json']);
    expect(npmRegistry.hits).toEqual([]);
    expect(json.status).toBe(2);
    expect(json.json?.found).toBe(false);
    expect(json.json?.ecosystem).toBe('npm');
    expect(json.json).not.toHaveProperty('score');
  });
});
