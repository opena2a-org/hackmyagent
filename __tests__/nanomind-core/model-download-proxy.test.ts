/**
 * The NanoMind model download honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY.
 *
 * `https.get` ignores those variables, so on a network that reaches the
 * internet only through a proxy the download went direct, failed, and the
 * scan fell back to vocabulary scoring. A local proxy with HTTPS_PROXY
 * pointing at it saw no request at all. The download now opens a CONNECT
 * tunnel through the proxy and runs TLS to the model host inside it.
 *
 * A proxy URL can carry a user name and password. The notice names the proxy
 * by host:port, and every test here that sets credentials asserts that
 * neither one, in any encoding, reaches stdout or stderr.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo, Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TMEClassifier } from '../../src/nanomind-core/inference/tme-classifier';
import {
  noProxyCovers,
  proxiedRequestOptions,
  resolveModelProxy,
} from '../../src/nanomind-core/inference/model-proxy';

const MODEL_URL = 'https://huggingface.co/opena2a/nanomind-security-classifier/resolve/x/tokenizer.json';
const CDN_URL = 'https://us.aws.cdn.hf.co/xet-bridge/abc';
const PROXY_VARIABLES = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY'];

const USER = 'proxy-user-7f3a';
const PASSWORD = 'p@ss:w0rd/9c1e';
const ENCODED_PASSWORD = encodeURIComponent(PASSWORD);

/** Every form of the credentials that must never reach an output. */
function credentialForms(): string[] {
  return [
    USER,
    PASSWORD,
    ENCODED_PASSWORD,
    Buffer.from(`${USER}:${PASSWORD}`).toString('base64'),
    Buffer.from(`${USER}:${ENCODED_PASSWORD}`).toString('base64'),
  ];
}

describe('resolveModelProxy', () => {
  it('goes direct when no proxy variable is set', () => {
    expect(resolveModelProxy(MODEL_URL, {})).toEqual({ kind: 'direct' });
  });

  it('uses HTTPS_PROXY and names it by host:port', () => {
    const route = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: 'http://proxy.corp.example:3128' });
    expect(route.kind).toBe('proxy');
    if (route.kind !== 'proxy') return;
    expect(route.proxy).toMatchObject({
      variable: 'HTTPS_PROXY',
      display: 'proxy.corp.example:3128',
      protocol: 'http:',
      host: 'proxy.corp.example',
      port: 3128,
    });
    expect(route.proxy.authorization).toBeUndefined();
  });

  it('uses HTTP_PROXY for an https:// URL when HTTPS_PROXY is not set', () => {
    const route = resolveModelProxy(MODEL_URL, { HTTP_PROXY: 'http://fallback.example:8080' });
    expect(route.kind === 'proxy' && route.proxy.variable).toBe('HTTP_PROXY');
    expect(route.kind === 'proxy' && route.proxy.display).toBe('fallback.example:8080');
  });

  it('prefers HTTPS_PROXY over HTTP_PROXY, and the lower-case name within each pair', () => {
    const both = resolveModelProxy(MODEL_URL, {
      HTTP_PROXY: 'http://plain.example:1',
      HTTPS_PROXY: 'http://secure.example:2',
    });
    expect(both.kind === 'proxy' && both.proxy.display).toBe('secure.example:2');
    const cased = resolveModelProxy(MODEL_URL, {
      HTTPS_PROXY: 'http://upper.example:1',
      https_proxy: 'http://lower.example:2',
    });
    expect(cased.kind === 'proxy' && cased.proxy.variable).toBe('https_proxy');
  });

  it('treats an empty or blank variable as unset', () => {
    expect(resolveModelProxy(MODEL_URL, { HTTPS_PROXY: '', HTTP_PROXY: '   ' })).toEqual({ kind: 'direct' });
    const route = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: '', HTTP_PROXY: 'http://next.example:3' });
    expect(route.kind === 'proxy' && route.proxy.variable).toBe('HTTP_PROXY');
  });

  it('reads a value with no scheme as an http:// proxy, and fills in the default port', () => {
    const bare = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: 'proxy.corp.example:3128' });
    expect(bare.kind === 'proxy' && bare.proxy.protocol).toBe('http:');
    expect(bare.kind === 'proxy' && bare.proxy.display).toBe('proxy.corp.example:3128');
    const http80 = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: 'http://proxy.corp.example' });
    expect(http80.kind === 'proxy' && http80.proxy.display).toBe('proxy.corp.example:80');
    const https443 = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: 'https://proxy.corp.example' });
    expect(https443.kind === 'proxy' && https443.proxy.display).toBe('proxy.corp.example:443');
  });

  it('turns credentials into a Proxy-Authorization value and keeps them out of the display form', () => {
    const route = resolveModelProxy(MODEL_URL, {
      HTTPS_PROXY: `http://${USER}:${ENCODED_PASSWORD}@proxy.corp.example:3128`,
    });
    expect(route.kind).toBe('proxy');
    if (route.kind !== 'proxy') return;
    expect(route.proxy.authorization).toBe(`Basic ${Buffer.from(`${USER}:${PASSWORD}`).toString('base64')}`);
    expect(route.proxy.display).toBe('proxy.corp.example:3128');
  });

  it('goes direct for a host NO_PROXY covers', () => {
    const env = (noProxy: string) => ({ HTTPS_PROXY: 'http://proxy.corp.example:3128', NO_PROXY: noProxy });
    expect(resolveModelProxy(MODEL_URL, env('huggingface.co'))).toEqual({ kind: 'direct' });
    expect(resolveModelProxy(CDN_URL, env('localhost, .hf.co'))).toEqual({ kind: 'direct' });
    expect(resolveModelProxy(CDN_URL, env('hf.co'))).toEqual({ kind: 'direct' });
    expect(resolveModelProxy(CDN_URL, env('*.hf.co'))).toEqual({ kind: 'direct' });
    expect(resolveModelProxy(MODEL_URL, env('*'))).toEqual({ kind: 'direct' });
    expect(resolveModelProxy(MODEL_URL, { ...env(''), no_proxy: 'huggingface.co' })).toEqual({ kind: 'direct' });
    // A NO_PROXY entry that only covers the CDN leaves the model host proxied.
    expect(resolveModelProxy(MODEL_URL, env('.hf.co')).kind).toBe('proxy');
  });

  it('goes direct for a NO_PROXY host even when the proxy variable cannot be used', () => {
    expect(resolveModelProxy(MODEL_URL, { HTTPS_PROXY: 'socks5://h:1080', NO_PROXY: 'huggingface.co' }))
      .toEqual({ kind: 'direct' });
  });

  it('reports a proxy it cannot use, without repeating the value', () => {
    const socks = resolveModelProxy(MODEL_URL, {
      HTTPS_PROXY: `socks5://${USER}:${ENCODED_PASSWORD}@socks.example:1080`,
    });
    expect(socks.kind).toBe('unusable');
    if (socks.kind !== 'unusable') return;
    expect(socks.variable).toBe('HTTPS_PROXY');
    expect(socks.reason).toContain('socks5');
    const invalid = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: `http://${USER}:${ENCODED_PASSWORD}@[bad` });
    expect(invalid).toEqual({ kind: 'unusable', variable: 'HTTPS_PROXY', reason: 'is not a valid URL' });
    for (const route of [socks, invalid]) {
      for (const form of credentialForms()) expect(JSON.stringify(route)).not.toContain(form);
    }
  });
});

describe('noProxyCovers', () => {
  it.each([
    ['huggingface.co', 443, 'huggingface.co', true],
    ['huggingface.co', 443, 'HuggingFace.co', true],
    ['huggingface.co', 443, 'huggingface.co:443', true],
    ['huggingface.co', 443, 'huggingface.co:8443', false],
    ['huggingface.co', 443, 'gingface.co', false],
    ['huggingface.co', 443, 'face.co', false],
    ['us.aws.cdn.hf.co', 443, 'cdn.hf.co', true],
    ['us.aws.cdn.hf.co', 443, 'evil-hf.co', false],
    ['huggingface.co', 443, 'a.example b.example,huggingface.co', true],
    ['huggingface.co', 443, ' , ', false],
  ])('%s:%d with NO_PROXY=%j -> %s', (host, port, noProxy, covered) => {
    expect(noProxyCovers(host, port, noProxy)).toBe(covered);
  });
});

/**
 * A local proxy that records each CONNECT request and its
 * Proxy-Authorization header. In `deny` mode it answers 407; in `tunnel` mode
 * it answers 200, records the first bytes the client sends through the
 * tunnel, and closes it, so nothing leaves the machine. `silent` never
 * answers the CONNECT request; `silent-tunnel` answers 200 and then says
 * nothing, so the TLS handshake inside the tunnel never completes.
 */
function startProxy(mode: 'deny' | 'tunnel' | 'silent' | 'silent-tunnel') {
  const connects: Array<{ target: string; authorization?: string }> = [];
  const tunnelBytes: Buffer[] = [];
  const sockets = new Set<Socket>();
  const server = http.createServer((_req, res) => { res.statusCode = 405; res.end(); });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('connect', (req, socket) => {
    connects.push({ target: String(req.url), authorization: req.headers['proxy-authorization'] });
    socket.on('error', () => { /* the client may reset the tunnel */ });
    if (mode === 'deny') {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n');
      return;
    }
    if (mode === 'silent') return;
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (mode === 'silent-tunnel') return;
    socket.once('data', (chunk: Buffer) => {
      tunnelBytes.push(chunk);
      socket.destroy();
    });
  });
  return new Promise<{
    port: number;
    connects: typeof connects;
    tunnelBytes: typeof tunnelBytes;
    close: () => Promise<void>;
  }>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        connects,
        tunnelBytes,
        close: () => new Promise((done) => {
          for (const socket of sockets) socket.destroy();
          server.close(() => done());
        }),
      });
    });
  });
}

describe('model download through a proxy', () => {
  let dir: string;
  let stderr: string[];
  let stdout: string[];
  let proxy: Awaited<ReturnType<typeof startProxy>> | null;

  beforeEach(() => {
    for (const name of PROXY_VARIABLES) vi.stubEnv(name, '');
    dir = mkdtempSync(join(tmpdir(), 'hma-model-proxy-'));
    stderr = [];
    stdout = [];
    proxy = null;
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
      stderr.push(String(chunk));
      return true;
    }) as typeof process.stderr.write);
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      stdout.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    if (proxy) await proxy.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const expectNoCredentials = () => {
    const output = stderr.join('') + stdout.join('');
    for (const form of credentialForms()) expect(output).not.toContain(form);
    expect(output).not.toContain('@127.0.0.1');
  };

  it('sends the first request through HTTPS_PROXY as a CONNECT tunnel with TLS to huggingface.co inside it', async () => {
    proxy = await startProxy('tunnel');
    vi.stubEnv('HTTPS_PROXY', `http://${USER}:${ENCODED_PASSWORD}@127.0.0.1:${proxy.port}`);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(proxy.connects).toHaveLength(1);
    expect(proxy.connects[0].target).toBe('huggingface.co:443');
    expect(proxy.connects[0].authorization).toBe(
      `Basic ${Buffer.from(`${USER}:${PASSWORD}`).toString('base64')}`,
    );
    // The first bytes in the tunnel are a TLS handshake record whose
    // ClientHello names huggingface.co: the request itself is encrypted.
    expect(proxy.tunnelBytes).toHaveLength(1);
    expect(proxy.tunnelBytes[0][0]).toBe(0x16);
    expect(proxy.tunnelBytes[0].includes(Buffer.from('huggingface.co'))).toBe(true);
    expect(proxy.tunnelBytes[0].includes(Buffer.from('GET '))).toBe(false);

    expect(stderr[0]).toContain(`through the proxy 127.0.0.1:${proxy.port} set in HTTPS_PROXY.`);
    expect(stderr).toHaveLength(3);
    expect(stderr[2]).toContain('NanoMind: model download failed: tokenizer.json:');
    expectNoCredentials();
  });

  it('uses HTTP_PROXY when HTTPS_PROXY is not set', async () => {
    proxy = await startProxy('deny');
    vi.stubEnv('HTTP_PROXY', `http://127.0.0.1:${proxy.port}`);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(proxy.connects.map((c) => c.target)).toEqual(['huggingface.co:443']);
    expect(proxy.connects[0].authorization).toBeUndefined();
    expect(stderr[0]).toContain(`through the proxy 127.0.0.1:${proxy.port} set in HTTP_PROXY.`);
  });

  it('says which proxy refused the tunnel, and with what status, without the credentials', async () => {
    proxy = await startProxy('deny');
    vi.stubEnv('HTTPS_PROXY', `http://${USER}:${ENCODED_PASSWORD}@127.0.0.1:${proxy.port}`);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(stderr[2]).toContain(
      `tokenizer.json: proxy 127.0.0.1:${proxy.port} answered the tunnel request with HTTP 407.`,
    );
    expect(stderr[2]).toContain('The classifier did not run');
    expectNoCredentials();
  });

  it('says which proxy could not be reached, without the credentials', async () => {
    const closed = await startProxy('deny');
    const port = closed.port;
    await closed.close();
    vi.stubEnv('HTTPS_PROXY', `http://${USER}:${ENCODED_PASSWORD}@127.0.0.1:${port}`);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(stderr[2]).toContain(`tokenizer.json: proxy 127.0.0.1:${port}: ECONNREFUSED.`);
    expectNoCredentials();
  });

  it('goes direct, and names no proxy, for a host NO_PROXY covers', async () => {
    proxy = await startProxy('deny');
    vi.stubEnv('HTTPS_PROXY', `http://${USER}:${ENCODED_PASSWORD}@127.0.0.1:${proxy.port}`);
    vi.stubEnv('NO_PROXY', 'localhost,huggingface.co,.hf.co');
    const calls: unknown[][] = [];
    vi.spyOn(https, 'get').mockImplementation(((...args: unknown[]) => {
      calls.push(args);
      const cb = args[args.length - 1] as (res: unknown) => void;
      const res = Object.assign(new PassThrough(), { statusCode: 404, headers: {} });
      process.nextTick(() => cb(res));
      return new EventEmitter();
    }) as unknown as typeof https.get);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(proxy.connects).toEqual([]);
    expect(calls).toHaveLength(1);
    // The direct request carries its idle bound and no tunnel.
    expect(calls[0]).toHaveLength(3);
    expect(Object.keys(calls[0][1] as object)).toEqual(['timeout']);
    expect(stderr[0]).not.toContain('through the proxy');
    expect(stderr[2]).toContain('HTTP 404 from huggingface.co');
    expectNoCredentials();
  });

  // The idle bound on a silent connection holds through a proxy as well: a
  // proxy that accepts the connection and then says nothing must not hold
  // the scan open.
  it('abandons a proxy that never answers the tunnel request', async () => {
    proxy = await startProxy('silent');
    vi.stubEnv('HTTPS_PROXY', `http://${USER}:${ENCODED_PASSWORD}@127.0.0.1:${proxy.port}`);

    const outcome = await Promise.race([
      TMEClassifier.downloadModel(dir, { idleTimeoutMs: 200 }),
      new Promise<'pending'>((resolve) => setTimeout(() => resolve('pending'), 10_000)),
    ]);

    expect(proxy.connects).toHaveLength(1);
    expect(outcome, 'download still pending 10s after a 200ms idle bound').toBe(false);
    expect(stderr[2]).toContain(
      `tokenizer.json: proxy 127.0.0.1:${proxy.port}: no answer to the tunnel request for 0.2s.`,
    );
    expectNoCredentials();
  });

  it('abandons a tunnel that opens and then goes silent', async () => {
    proxy = await startProxy('silent-tunnel');
    vi.stubEnv('HTTPS_PROXY', `http://127.0.0.1:${proxy.port}`);

    const outcome = await Promise.race([
      TMEClassifier.downloadModel(dir, { idleTimeoutMs: 200 }),
      new Promise<'pending'>((resolve) => setTimeout(() => resolve('pending'), 10_000)),
    ]);

    expect(proxy.connects).toHaveLength(1);
    expect(outcome, 'download still pending 10s after a 200ms idle bound').toBe(false);
    expect(stderr[2]).toContain('tokenizer.json: no data received for 0.2s.');
  });

  it('makes no request when the proxy variable names a scheme it cannot use, and says so', async () => {
    vi.stubEnv('HTTPS_PROXY', `socks5://${USER}:${ENCODED_PASSWORD}@127.0.0.1:1080`);
    const get = vi.spyOn(https, 'get');

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);

    expect(get).not.toHaveBeenCalled();
    expect(stderr[2]).toContain('tokenizer.json: HTTPS_PROXY is set but names a socks5 proxy');
    expect(stderr[2]).toContain('so no request was made');
    expectNoCredentials();
  });
});

describe('proxiedRequestOptions', () => {
  it('keeps the Host header to the model host, with no port', async () => {
    const proxy = await startProxy('deny');
    try {
      const route = resolveModelProxy(MODEL_URL, { HTTPS_PROXY: `http://127.0.0.1:${proxy.port}` });
      if (route.kind !== 'proxy') throw new Error('expected a proxy route');
      const request = https.request(MODEL_URL, proxiedRequestOptions(route.proxy, MODEL_URL));
      const failed = new Promise<void>((resolve) => request.on('error', () => resolve()));
      expect(request.getHeader('host')).toBe('huggingface.co');
      request.end();
      await failed;
    } finally {
      await proxy.close();
    }
  });
});
