/**
 * #444 — the liveness precondition settles a run in one request when the
 * target cannot be connected to at all, and never vetoes a live target.
 *
 * Measured on 044301c5: `attack http://127.0.0.1:9/x` sent all 111 payloads
 * and took ~112 s to reach the answered-count gate's NOT MEASURED. Port 9 is a
 * port the Fetch standard blocks: `fetch` refuses it before opening a socket,
 * with `cause.message === 'bad port'` and no errno, which the probe read as
 * inconclusive. A refused connection on an ordinary port already settled in
 * one request (ECONNREFUSED); that is pinned here too, with the two
 * connection-level codes the issue names beside it.
 *
 * The other direction is the one that matters most: a live endpoint that
 * rejects or drops the PROBE but answers payloads must still be measured, or
 * a slow-but-correct path becomes a fast false negative.
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AttackScanner } from '../../src/attack/scanner';
import { getPayloads } from '../../src/attack/payloads';
import type { AttackTarget } from '../../src/attack/types';

const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

function listen(handler: http.RequestListener): Promise<number> {
  const server = http.createServer(handler);
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

/** A port nothing listens on: bound once to get it from the OS, then released. */
async function freePort(): Promise<number> {
  const server = http.createServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((r) => server.close(() => r()));
  return port;
}

const TWO_PAYLOADS = getPayloads(undefined, 'passive').slice(0, 2).map((p) => p.id);

function api(url: string): AttackTarget {
  return { url, type: 'api', apiFormat: 'openai' };
}

describe('#444: an unconnectable target is settled by the probe alone', () => {
  it('a Fetch-blocked port (9) is NOT MEASURED in one step, naming the blocked port', async () => {
    const scanner = new AttackScanner({ delay: 0, timeout: 5000 });
    const started = Date.now();
    const report = await scanner.scan(api('http://127.0.0.1:9/x'));
    expect(Date.now() - started).toBeLessThan(5000);
    expect(report.riskRating).toBe('unmeasured');
    expect(report.results).toHaveLength(0);
    expect(report.verdict).toMatchObject({ measured: false, reason: 'target-unreachable' });
    expect((report.verdict as { detail: string }).detail).toMatch(/blocked port/);
  });

  it('a refused connection is NOT MEASURED in one step (ECONNREFUSED)', async () => {
    const port = await freePort();
    const scanner = new AttackScanner({ delay: 0, timeout: 5000 });
    const started = Date.now();
    const report = await scanner.scan(api(`http://127.0.0.1:${port}/x`));
    expect(Date.now() - started).toBeLessThan(5000);
    expect(report.riskRating).toBe('unmeasured');
    expect(report.results).toHaveLength(0);
    expect((report.verdict as { detail: string }).detail).toContain('ECONNREFUSED');
  });

  it('probeLiveness treats no-route errors as definitive and a reset as inconclusive', async () => {
    const scanner = new AttackScanner();
    const realFetch = globalThis.fetch;
    const failWith = (cause: Record<string, unknown>) => {
      globalThis.fetch = (async () => { throw Object.assign(new TypeError('fetch failed'), { cause }); }) as typeof fetch;
    };
    try {
      for (const code of ['EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'ECONNREFUSED']) {
        failWith({ code, message: `connect ${code}` });
        expect(await scanner.probeLiveness(api('http://agent.test/x'), 1000), code).toMatchObject({ reachable: false });
      }
      for (const code of ['ECONNRESET', 'ETIMEDOUT', 'UND_ERR_SOCKET', 'EAI_AGAIN']) {
        failWith({ code, message: `x ${code}` });
        expect(await scanner.probeLiveness(api('http://agent.test/x'), 1000), code).toEqual({ inconclusive: true });
      }
      // The blocked-port signal needs BOTH halves: fetch's own wording and no errno.
      failWith({ message: 'bad port', code: 'ECONNRESET' });
      expect(await scanner.probeLiveness(api('http://agent.test/x'), 1000)).toEqual({ inconclusive: true });
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

describe('#444: a live endpoint that rejects the probe is still measured', () => {
  it('drops the probe connection, answers payloads: the suite runs and is measured', async () => {
    let requests = 0;
    const port = await listen((req, res) => {
      requests++;
      if (requests === 1) {
        req.socket.destroy(); // the probe: reset, no response
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content: "I can't help with that." } }] }));
    });
    const scanner = new AttackScanner({ delay: 0, timeout: 5000 });
    const report = await scanner.scan(api(`http://127.0.0.1:${port}/x`), { payloadIds: TWO_PAYLOADS });
    expect(report.riskRating).not.toBe('unmeasured');
    expect(report.results).toHaveLength(TWO_PAYLOADS.length);
    expect(report.summary.answered).toBe(TWO_PAYLOADS.length);
  });

  it('answers the probe with 400 and payloads with 200: the suite runs and is measured', async () => {
    const port = await listen((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        if (body.includes('ping')) {
          res.writeHead(400).end('{"error":"unsupported"}');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ choices: [{ message: { content: "I can't help with that." } }] }));
      });
    });
    const scanner = new AttackScanner({ delay: 0, timeout: 5000 });
    const report = await scanner.scan(api(`http://127.0.0.1:${port}/x`), { payloadIds: TWO_PAYLOADS });
    expect(report.riskRating).not.toBe('unmeasured');
    expect(report.summary.answered).toBe(TWO_PAYLOADS.length);
  });
});

describe('delay option', () => {
  it('honours an explicit 0 and falls back to the default for a non-finite or negative value', () => {
    const delayOf = (s: AttackScanner) => (s as unknown as { options: { delay: number } }).options.delay;
    expect(delayOf(new AttackScanner({ delay: 0 }))).toBe(0);
    expect(delayOf(new AttackScanner({ delay: 250 }))).toBe(250);
    expect(delayOf(new AttackScanner({}))).toBe(1000);
    expect(delayOf(new AttackScanner({ delay: Number.NaN }))).toBe(1000);
    expect(delayOf(new AttackScanner({ delay: -5 }))).toBe(1000);
  });
});
