/**
 * The capture registry answers at its base URL whichever loopback address the
 * host resolves localhost to (#1147).
 *
 * The outbound contract tests hand the CLI `http://localhost:<port>`. The
 * registry listened on `localhost`, which takes the first answer of a lookup
 * made without hints, while Node looks up the host name of a connection with
 * AI_ADDRCONFIG. Where the first lists ::1 first and the second leaves IPv6
 * out, the registry listened on ::1, the CLI dialled 127.0.0.1, and the
 * contract tests captured no request.
 *
 * Each case dials the base URL with the resolver's answer pinned through the
 * request's own `lookup`, standing in for a host that answers that way. The
 * last cases start the registry with a preload that fails its listens on ::1
 * with EADDRNOTAVAIL or EAFNOSUPPORT (the codes for an address the host does
 * not have and for an address family it does not support) or with EADDRINUSE
 * (the code for an address another process holds).
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { LookupFunction } from 'node:net';
import { startCaptureRegistry, type CaptureRegistry } from '../helpers/outbound-capture';
import { tempDir } from '../helpers/temp-dir';

const HAS_IPV6_LOOPBACK = Object.values(os.networkInterfaces()).some((addrs) => (addrs ?? []).some((a) => a.address === '::1'));

/** A resolver that answers every host name with `address` alone. */
function resolvesTo(address: string): LookupFunction {
  const family = address.includes(':') ? 6 : 4;
  return (_hostname, options, callback) => {
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

/** The status of `GET <base>/health`, with localhost resolved to `address` alone. */
function healthVia(registry: CaptureRegistry, address: string): Promise<number> {
  return new Promise((resolve, reject) => {
    // No agent: a pooled connection would be reused without a lookup.
    http.get(`${registry.base}/health`, { agent: false, lookup: resolvesTo(address) }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    }).on('error', reject);
  });
}

/**
 * Writes a preload that fails the registry's first `times` listens on ::1 with
 * `code`, and appends `code` to `log` for each one it fails.
 */
function failingIpv6Listens(dir: string, code: string, times: number): { preload: string; log: string } {
  const preload = path.join(dir, `ipv6-listen-${code}.cjs`);
  const log = path.join(dir, `ipv6-listen-${code}.log`);
  fs.writeFileSync(preload, [
    "'use strict';",
    "const fs = require('node:fs');",
    "const net = require('node:net');",
    `const code = ${JSON.stringify(code)};`,
    `let left = ${times};`,
    'const listen = net.Server.prototype.listen;',
    'net.Server.prototype.listen = function (...args) {',
    "  const host = typeof args[1] === 'string' ? args[1] : (args[0] && typeof args[0] === 'object' ? args[0].host : undefined);",
    "  if (host !== '::1' || left === 0) return listen.apply(this, args);",
    '  left -= 1;',
    `  fs.appendFileSync(${JSON.stringify(log)}, code + '\\n');`,
    "  const err = Object.assign(new Error('listen ' + code + ' ::1'), { code, syscall: 'listen', address: '::1' });",
    "  process.nextTick(() => this.emit('error', err));",
    '  return this;',
    '};',
    '',
  ].join('\n'));
  return { preload, log };
}

function logged(log: string): string[] {
  return fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean) : [];
}

function routes(registry: CaptureRegistry): string[] {
  return registry.captured().map((q) => `${q.method} ${q.url}`);
}

describe('the capture registry answers at its base URL whichever loopback address localhost resolves to (#1147)', () => {
  it('answers a connection whose lookup of localhost gives 127.0.0.1 alone', async () => {
    const registry = await startCaptureRegistry(tempDir('hma-capture-loopback-'));
    try {
      expect(await healthVia(registry, '127.0.0.1')).toBe(200);
      expect(routes(registry)).toEqual(['GET /health']);
    } finally {
      registry.stop();
    }
  });

  it.runIf(HAS_IPV6_LOOPBACK)('answers a connection whose lookup of localhost gives ::1 alone, at the same port', async () => {
    const registry = await startCaptureRegistry(tempDir('hma-capture-loopback-'));
    try {
      expect(await healthVia(registry, '::1')).toBe(200);
      expect(await healthVia(registry, '127.0.0.1')).toBe(200);
      expect(routes(registry)).toEqual(['GET /health', 'GET /health']);
    } finally {
      registry.stop();
    }
  });

  it.each(['EADDRNOTAVAIL', 'EAFNOSUPPORT'])('starts after one try where every listen on ::1 fails with %s, and answers on 127.0.0.1', async (code) => {
    const dir = tempDir('hma-capture-loopback-');
    const { preload, log } = failingIpv6Listens(dir, code, 100);
    const registry = await startCaptureRegistry(dir, { preload });
    try {
      expect(logged(log)).toEqual([code]);
      expect(await healthVia(registry, '127.0.0.1')).toBe(200);
      expect(routes(registry)).toEqual(['GET /health']);
    } finally {
      registry.stop();
    }
  });

  it.runIf(HAS_IPV6_LOOPBACK)('starts again where its first listen on ::1 fails with EADDRINUSE, and answers on both addresses at the port it reports', async () => {
    const dir = tempDir('hma-capture-loopback-');
    const { preload, log } = failingIpv6Listens(dir, 'EADDRINUSE', 1);
    const registry = await startCaptureRegistry(dir, { preload });
    try {
      expect(logged(log)).toEqual(['EADDRINUSE']);
      expect(await healthVia(registry, '::1')).toBe(200);
      expect(await healthVia(registry, '127.0.0.1')).toBe(200);
      expect(routes(registry)).toEqual(['GET /health', 'GET /health']);
    } finally {
      registry.stop();
    }
  });
});
