/**
 * `wild` against a target that answered no attack page with a 2xx status
 * scored the empty (or all-404) set 100/100 (strong) and exited 0, so an
 * unreachable host passed the gate. Only a 2xx page counts as scanned; with
 * none, the result is "not measured", carries no score or rating, and exits
 * 2. A target that serves pages still scores as before.
 *
 * Every target is on 127.0.0.1: a local server, or a port nothing listens on.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { isSuccessStatus } from '../../src/wild';

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const INDEX = path.join(ROOT, 'dist', 'index.js');

/** Async spawn: the local servers live in this process and must keep answering. */
function run(entry: string, args: string[]): Promise<{ status: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [entry, ...args], {
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, out, err }));
  });
}

function serve(handler: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

/** A port that refuses connections: bound once, then released. */
async function closedPort(): Promise<string> {
  const s = await serve((_req, res) => res.end());
  await s.close();
  return s.url;
}

const ARGS = ['--category', 'jailbreak', '--delay', '0', '--timeout', '2000'];

describe('isSuccessStatus', () => {
  it('admits 2xx and nothing else', () => {
    for (const ok of [200, 201, 204, 299]) expect(isSuccessStatus(ok), String(ok)).toBe(true);
    for (const bad of [0, 199, 300, 301, 404, 500, 200.5, NaN]) expect(isSuccessStatus(bad), String(bad)).toBe(false);
  });
});

describe('wild reports "not measured" when no attack page answered 2xx', { timeout: 120_000 }, () => {
  let all404: { url: string; close: () => Promise<void> };
  let all500: { url: string; close: () => Promise<void> };
  let onePage: { url: string; close: () => Promise<void> };
  let unreachable: string;

  beforeAll(async () => {
    assertDistFresh();
    all404 = await serve((_req, res) => { res.statusCode = 404; res.end('<html><body>Not Found</body></html>'); });
    all500 = await serve((_req, res) => { res.statusCode = 500; res.end('<html><body>error</body></html>'); });
    onePage = await serve((req, res) => {
      if (req.url === '/attacks/jailbreak/1') {
        res.setHeader('content-type', 'text/html');
        res.end('<html><head><title>Attack</title></head><body><p>Hello</p></body></html>');
      } else {
        res.statusCode = 404;
        res.end('Not Found');
      }
    });
    unreachable = await closedPort();
  });

  afterAll(async () => {
    await Promise.all([all404?.close(), all500?.close(), onePage?.close()]);
  });

  const cases: Array<[string, () => string]> = [
    ['an unreachable target', () => unreachable],
    ['a target where every page is 404', () => all404.url],
    ['a target where every page is 500', () => all500.url],
  ];

  for (const [name, target] of cases) {
    it(`${name}: text output says not measured, gives no score, exits 2`, async () => {
      for (const entry of [CLI, INDEX]) {
        const r = await run(entry, ['wild', target(), ...ARGS]);
        expect(r.status, r.out + r.err).toBe(2);
        expect(r.out).toContain('not measured');
        expect(r.out).not.toContain('/100');
        expect(r.out).not.toMatch(/\b(strong|good|moderate|needs-attention|critical)\b/);
        expect(r.out).toContain('Attack Pages (0 scanned)');
      }
    });

    it(`${name}: JSON output has measured false and a null score and rating, exits 2`, async () => {
      const r = await run(CLI, ['wild', target(), ...ARGS, '--json']);
      expect(r.status, r.out + r.err).toBe(2);
      const report = JSON.parse(r.out);
      expect(report.measured).toBe(false);
      expect(report.pagesScanned).toBe(0);
      expect(report.wildResilienceScore).toBeNull();
      expect(report.resilienceRating).toBeNull();
      expect(report.notMeasuredReason).toMatch(/no attack page answered with a 2xx status: of 5 attack pages/);
    });
  }

  it('a target that serves one page still scores, and the score counts the 404 pages as before', async () => {
    const r = await run(CLI, ['wild', onePage.url, ...ARGS, '--json']);
    expect(r.status, r.out + r.err).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.measured).toBe(true);
    expect(report.notMeasuredReason).toBeUndefined();
    expect(report.pagesScanned).toBe(1);
    // Every fetched page stays in the report and in the score: tiers 1-5 of
    // one category, no payload, gives 100 - (5 * 2) - (1 * 2) = 88.
    expect(report.pages).toHaveLength(5);
    expect(report.wildResilienceScore).toBe(88);
    expect(report.resilienceRating).toBe('strong');

    const text = await run(CLI, ['wild', onePage.url, ...ARGS]);
    expect(text.status, text.out + text.err).toBe(0);
    expect(text.out).toContain('Wild Resilience Score: 88/100 (strong)');
    expect(text.out).toContain('Attack Pages (1 scanned)');
    expect(text.out).not.toContain('not measured');
  });
});
