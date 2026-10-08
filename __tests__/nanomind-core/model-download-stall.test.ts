// Regression: a stalled model download hung `secure` until something killed it
// (#542).
//
// `machine-posture-not-scored.test.ts` failed intermittently under full-suite
// load. Every scan in that file runs under a fresh HOME, and a HOME with no
// model cache makes `secure` download the NanoMind model before it writes its
// report. The download had no bound: a connection that was accepted and then
// went silent held the scan open until the test's 120s spawn budget killed it,
// with nothing on stdout. Measured with the download stalled on purpose:
//
//   ms 120010 status null signal SIGTERM stdoutLen 0
//   JSON.parse: Unexpected end of JSON input
//
// Which file flaked was a matter of which scan drew the stalled connection.
// These cases stall the download on demand instead of waiting for the network
// to do it: real sockets that accept and then say nothing.

import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { createServer as createNetServer, type Server as NetServer, type Socket } from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { TMEClassifier } from '../../src/nanomind-core/inference/tme-classifier';
import { assertDistFresh } from '../helpers/dist-freshness';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

const created: string[] = [];
const track = (d: string) => (created.push(d), d);
afterAll(() => {
  for (const d of created) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// A proxy variable in the caller's shell sends the download through a tunnel
// to that proxy, around the stalled endpoints below, so these cases clear them
// and route every request themselves. model-download-proxy.test.ts covers
// proxies.
const PROXY_VARIABLES = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY'];

/** A server that accepts every connection and never writes a byte. */
async function silentServer(): Promise<{ port: number; connections: () => number; close: () => Promise<void> }> {
  const sockets: Socket[] = [];
  const server: NetServer = createNetServer((s) => { sockets.push(s); });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  return {
    port,
    connections: () => sockets.length,
    close: () => new Promise<void>((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    }),
  };
}

/** Settles with the promise's value, or with `'pending'` once `ms` has passed. */
function within<T>(p: Promise<T>, ms: number): Promise<T | 'pending'> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<'pending'>((resolve) => { timer = setTimeout(() => resolve('pending'), ms); });
  return Promise.race([p, deadline]).finally(() => clearTimeout(timer));
}

describe('a stalled model download fails instead of hanging', () => {
  const closers: Array<() => Promise<void>> = [];
  beforeEach(() => {
    for (const name of PROXY_VARIABLES) vi.stubEnv(name, '');
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    while (closers.length) await closers.pop()!();
  });

  /**
   * Route the classifier's HuggingFace requests to a local port over plain
   * HTTP, keeping every option the classifier set (the idle bound is one).
   */
  function routeDownloadsTo(port: number) {
    vi.spyOn(https, 'get').mockImplementation(((url: string | URL, opts: https.RequestOptions, cb: (res: http.IncomingMessage) => void) => {
      return http.get({ ...opts, agent: undefined, protocol: 'http:', host: '127.0.0.1', port, path: new URL(String(url)).pathname }, cb);
    }) as unknown as typeof https.get);
  }

  it('a connection that never answers is abandoned and leaves no partial file', async () => {
    const server = await silentServer();
    closers.push(server.close);
    routeDownloadsTo(server.port);
    const dir = track(mkdtempSync(join(tmpdir(), 'hma-dl-silent-')));

    const outcome = await within(TMEClassifier.downloadModel(dir, { idleTimeoutMs: 200 }), 10_000);

    // Non-vacuous: the download really did reach the stalled endpoint.
    expect(server.connections()).toBeGreaterThan(0);
    expect(outcome, 'download still pending 10s after a 200ms idle bound').toBe(false);
    expect(existsSync(join(dir, 'tokenizer.json'))).toBe(false);
  });

  it('a body that stops part-way is abandoned too, not left waiting for the rest', async () => {
    // Headers and a first chunk arrive, then nothing: the stall happens after
    // the response handler has already piped into the file.
    const sockets: Socket[] = [];
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-length': '1000000' });
      res.write('x'.repeat(64));
    });
    server.on('connection', (s) => sockets.push(s));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    closers.push(() => new Promise<void>((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    }));
    routeDownloadsTo((server.address() as { port: number }).port);
    const dir = track(mkdtempSync(join(tmpdir(), 'hma-dl-partial-')));

    const outcome = await within(TMEClassifier.downloadModel(dir, { idleTimeoutMs: 200 }), 10_000);

    expect(sockets.length).toBeGreaterThan(0);
    expect(outcome, 'download still pending 10s after a 200ms idle bound').toBe(false);
    expect(existsSync(join(dir, 'tokenizer.json'))).toBe(false);
  });
});

// The case that flaked, end to end: a `secure` scan under a fresh HOME whose
// path carries a space and a quote, with the model download stalled. It has to
// return its report on its own, inside a budget well short of the old hang.
describe('secure finishes its report when the model download stalls', () => {
  // A checkout that has not built fails here, naming the command to run; the
  // download cases above load the source and still report on their own.
  beforeAll(assertDistFresh);

  it('the hostile-HOME scan from machine-posture-not-scored completes', async () => {
    const server = await silentServer();
    try {
      const work = track(mkdtempSync(join(tmpdir(), 'hma-dl-spawn-')));
      // Loaded into the CLI process: HuggingFace requests go to the silent
      // server; anything else is untouched.
      const preload = join(work, 'stall-model-download.cjs');
      writeFileSync(preload, [
        "const http = require('node:http');",
        "const https = require('node:https');",
        'const original = https.get;',
        'https.get = function (url, opts, cb) {',
        "  if (!String(url).startsWith('https://huggingface.co/')) return original.apply(this, arguments);",
        "  if (typeof opts === 'function') { cb = opts; opts = {}; }",
        "  return http.get({ ...opts, agent: undefined, protocol: 'http:', host: '127.0.0.1',",
        '    port: Number(process.env.HMA_TEST_STALL_PORT), path: new URL(String(url)).pathname }, cb);',
        '};',
        '',
      ].join('\n'));

      const hostile = track(mkdtempSync(join(tmpdir(), "hma-dl-ho me'x-")));
      const skillDir = join(hostile, '.openclaw', 'skills', 'harvester');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(join(skillDir, 'SKILL.md'), '---\nname: harvester\ndescription: collects local context\n---\n');
      const target = track(mkdtempSync(join(tmpdir(), 'hma-dl-target-')));
      writeFileSync(join(target, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }));

      const env: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: hostile,
        // Must not be '1': that skips the machine-posture section this
        // scan is checked against.
        OPENA2A_CORPUS_DETERMINISTIC: '',
        NODE_OPTIONS: `--require ${JSON.stringify(preload)}`,
        HMA_TEST_STALL_PORT: String(server.port),
      };
      for (const name of PROXY_VARIABLES) delete env[name];

      const BUDGET_MS = 60_000;
      const started = Date.now();
      const r = await new Promise<{ status: number | null; signal: NodeJS.Signals | null; stdout: string }>((resolve) => {
        const child = spawn(process.execPath, [CLI, 'secure', target, '--ci', '--json'], {
          env,
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        let stdout = '';
        child.stdout.on('data', (d) => { stdout += d; });
        const kill = setTimeout(() => child.kill('SIGKILL'), BUDGET_MS);
        child.on('close', (status, signal) => { clearTimeout(kill); resolve({ status, signal, stdout }); });
      });
      const elapsed = Date.now() - started;

      // Non-vacuous: the scan did try to download, and that download stalled.
      expect(server.connections()).toBeGreaterThan(0);
      expect(r.signal, `scan was killed after ${elapsed}ms instead of finishing`).toBeNull();
      const data = JSON.parse(r.stdout.trim());
      const openclaw = (data.machinePosture || []).find((m: { name: string }) => m.name === 'OpenClaw');
      expect(openclaw).toBeDefined();
    } finally {
      await server.close();
    }
  });
});
