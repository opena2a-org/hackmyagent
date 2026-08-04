/**
 * End-to-end integration test for `hackmyagent trust --grant`.
 *
 * Mirrors the structure of opena2a-cli's protect-grant-integration test
 * (opena2a-org/opena2a#179). The Secretless broker is the policy decision
 * point; this test stands up a minimal fake broker that speaks AAP §6 over a
 * Unix socket and asserts the gate is load-bearing:
 *   1. Refuses --grant without --atx.
 *   2. Proceeds when broker authorizes (200).
 *   3. Hard-fails 3 on uniform opaque denial (403).
 *   4. Hard-fails 6 on non-200/non-403 statuses WITHOUT echoing the broker body.
 *   5. Rejects structurally invalid + oversized ATX before contacting the broker.
 *   6. Sanitizes ANSI escapes in user-supplied grant references.
 */
import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { trustAapGate } from '../../src/aap';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const CLI_BIN = path.join(__dirname, '..', '..', 'dist', 'cli.js');

interface FakeBroker {
  socketPath: string;
  tokenPath: string;
  token: string;
  server: http.Server;
  next: { status: number; body: unknown };
  calls: number;
  lastBody?: string;
  close(): Promise<void>;
}

async function startFakeBroker(tmpDir: string): Promise<FakeBroker> {
  const socketPath = path.join(tmpDir, 'broker.sock');
  const tokenPath = path.join(tmpDir, 'broker.token');
  const token = 'hma-trust-integ-' + Math.random().toString(36).slice(2);
  fs.writeFileSync(tokenPath, token, { mode: 0o600 });

  const broker: FakeBroker = {
    socketPath,
    tokenPath,
    token,
    server: undefined as unknown as http.Server,
    next: { status: 200, body: { result: { status: 200, body: { authorized: true } } } },
    calls: 0,
    async close() {
      await new Promise<void>((resolve) => broker.server.close(() => resolve()));
    },
  };

  broker.server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      broker.calls += 1;
      broker.lastBody = Buffer.concat(chunks).toString('utf-8');
      const body = JSON.stringify(broker.next.body);
      res.writeHead(broker.next.status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      });
      res.end(body);
    });
  });

  await new Promise<void>((resolve, reject) => {
    broker.server.once('error', reject);
    broker.server.listen(socketPath, () => resolve());
  });

  return broker;
}

function writeAtxFixture(dir: string): string {
  const atxPath = path.join(dir, 'atx.json');
  fs.writeFileSync(
    atxPath,
    JSON.stringify({
      atcVersion: '1.0',
      agentId: 'hackmyagent_trust_cli',
      agentDid: 'did:opena2a:agent:opena2a-org/hackmyagent',
      version: '0.23.6',
      contentHash: 'sha256:test',
      issuerDid: 'did:opena2a:authority:opena2a.org',
      trustLevel: 4,
      trustScore: 0.95,
      issuedAt: '2026-05-25T00:00:00Z',
      expiresAt: '2026-06-30T00:00:00Z',
      capabilities: ['trust:read'],
      signatures: [],
    }),
  );
  return atxPath;
}

describe('hackmyagent trust --grant (AAP gate)', () => {
  let tmpDir: string;
  let broker: FakeBroker;
  let stderr: string;
  let stdout: string;
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  const origStdoutWrite = process.stdout.write.bind(process.stdout);

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aap-trust-'));
    broker = await startFakeBroker(tmpDir);
    stderr = '';
    stdout = '';
    (process.stderr.write as any) = (chunk: any) => {
      stderr += typeof chunk === 'string' ? chunk : String(chunk);
      return true;
    };
    (process.stdout.write as any) = (chunk: any) => {
      stdout += typeof chunk === 'string' ? chunk : String(chunk);
      return true;
    };
  });

  afterEach(async () => {
    (process.stderr.write as any) = origStderrWrite;
    (process.stdout.write as any) = origStdoutWrite;
    await broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('refuses --grant without --atx (exit 2, broker never contacted)', async () => {
    const code = await trustAapGate({ grant: 'grant://hackmyagent-trust' });
    expect(code).toBe(2);
    expect(broker.calls).toBe(0);
    expect(stderr).toMatch(/--grant requires --atx/);
  });

  it('proceeds with exit 0 when the broker authorizes (200)', async () => {
    broker.next = { status: 200, body: { result: { status: 200, body: { authorized: true } } } };
    const atxPath = writeAtxFixture(tmpDir);

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      packageName: 'express',
    });

    expect(code).toBe(0);
    expect(broker.calls).toBe(1);
    const sent = JSON.parse(broker.lastBody!);
    expect(sent.agentId).toBe('hackmyagent_trust_cli');
    expect(sent.grant).toBe('grant://hackmyagent-trust');
    expect(sent.atx.agentId).toBe('hackmyagent_trust_cli');
    expect(sent.operation.method).toBe('GET');
    expect(sent.operation.path).toBe('/trust/check');
    expect(sent.operation.query.package).toBe('express');
  });

  it('hard-fails 3 with an actionable message on 403 (AAP §6.6)', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const atxPath = writeAtxFixture(tmpDir);

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      packageName: 'express',
    });

    expect(code).toBe(3);
    expect(broker.calls).toBe(1);
    expect(stderr).toMatch(/AAP broker denied/);
    expect(stderr).toMatch(/Next step/);
    expect(stderr).toMatch(/grant:\/\/hackmyagent-trust/);
    expect(stderr).toMatch(/\.secretless-ai\/policies/);
  });

  it('hard-fails 4 with a broker-start hint when the socket is unreachable', async () => {
    await broker.close();
    const atxPath = writeAtxFixture(tmpDir);

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
    });

    expect(code).toBe(4);
    expect(stderr).toMatch(/AAP broker unreachable/);
    expect(stderr).toMatch(/secretless broker start/);
  });

  it('500 response: returns exit 6 and does NOT echo the broker body to stderr', async () => {
    broker.next = {
      status: 500,
      body: { error: 'db: cross-tenant lookup for tenantA failed', secret_host: 'api.internal.example' },
    };
    const atxPath = writeAtxFixture(tmpDir);

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
    });

    expect(code).toBe(6);
    expect(stderr).toMatch(/status 500/);
    expect(stderr).not.toContain('cross-tenant');
    expect(stderr).not.toContain('tenantA');
    expect(stderr).not.toContain('api.internal.example');
  });

  it('rejects a structurally-invalid ATX before contacting the broker', async () => {
    const atxPath = path.join(tmpDir, 'bad-atx.json');
    fs.writeFileSync(atxPath, JSON.stringify({ agentId: 'no-atc-version' }));

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
    });
    expect(code).toBe(2);
    expect(broker.calls).toBe(0);
    expect(stderr).toMatch(/not a valid ATX/);
  });

  it('rejects an oversized ATX file (>256 KiB) before read', async () => {
    const atxPath = path.join(tmpDir, 'huge-atx.json');
    fs.writeFileSync(atxPath, 'x'.repeat(300 * 1024));

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
    });
    expect(code).toBe(2);
    expect(broker.calls).toBe(0);
    expect(stderr).toMatch(/expected <= /);
  });

  it('emits a JSON-shaped denial when json: true', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const atxPath = writeAtxFixture(tmpDir);

    const code = await trustAapGate({
      grant: 'grant://hackmyagent-trust',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      packageName: 'express',
      json: true,
    });

    expect(code).toBe(3);
    const jsonLine = stdout.trim().split('\n').find((l) => l.startsWith('{'));
    expect(jsonLine).toBeDefined();
    const parsed = JSON.parse(jsonLine!);
    expect(parsed.status).toBe('aap-denied');
    expect(parsed.grant).toBe('grant://hackmyagent-trust');
    expect(parsed.packageName).toBe('express');
    expect(parsed.remediation).toMatch(/grant:\/\/hackmyagent-trust/);
  });

  // Mode-interaction guard. The gate authorizes ONE trust query. Letting
  // --grant combine with --audit or --batch would have the broker authorize
  // one query while HMA silently fans out to up to 100 Registry lookups
  // (breaks AAP §6.6 audit-attribution). The CLI rejects the combination
  // explicitly at exit 2 before any broker round-trip.
  describe('--grant mode-interaction guards (CLI exit codes)', () => {
    const skipIfNoBuild = fs.existsSync(CLI_BIN) ? it : it.skip;

    skipIfNoBuild('rejects --grant with --audit (exit 2, broker never contacted)', () => {
      const result = spawnSync('node', [
        CLI_BIN, 'trust',
        '--grant', 'grant://hackmyagent-trust',
        '--atx', '/tmp/atx.json',
        '--audit', '/tmp/package.json',
      ], { encoding: 'utf-8' });
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/--grant cannot be combined with --audit or --batch/);
    });

    skipIfNoBuild('rejects --grant with --batch (exit 2)', () => {
      const result = spawnSync('node', [
        CLI_BIN, 'trust',
        '--grant', 'grant://hackmyagent-trust',
        '--atx', '/tmp/atx.json',
        '--batch', 'a', 'b', 'c',
      ], { encoding: 'utf-8' });
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/--grant cannot be combined with --audit or --batch/);
    });

    skipIfNoBuild('rejects --grant with no positional package (exit 2)', () => {
      const result = spawnSync('node', [
        CLI_BIN, 'trust',
        '--grant', 'grant://hackmyagent-trust',
        '--atx', '/tmp/atx.json',
      ], { encoding: 'utf-8' });
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/--grant requires a package name/);
    });
  });

  it('sanitizes ANSI control characters in the grant reference for stderr output', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const atxPath = writeAtxFixture(tmpDir);
    const evilGrant = 'grant://x\x1b[2J\x1b[H\x1b[31mFAKE FATAL\x1b[0m';

    const code = await trustAapGate({
      grant: evilGrant,
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
    });

    expect(code).toBe(3);
    expect(stderr).not.toContain('\x1b[2J');
    expect(stderr).toMatch(/AAP broker denied/);
  });
});
