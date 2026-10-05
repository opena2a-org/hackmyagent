/**
 * Proxy support for the NanoMind model download.
 *
 * `https.get` ignores HTTPS_PROXY, HTTP_PROXY and NO_PROXY unless Node is
 * started with NODE_USE_ENV_PROXY, which Node 20 does not have. On a network
 * that reaches the internet only through a proxy, the download went direct
 * and failed, and the scan fell back to vocabulary scoring. This module picks
 * the proxy for a model URL from those variables and opens a CONNECT tunnel
 * through it, using only Node built-ins.
 *
 * TLS runs end to end with the model host inside the tunnel, with the usual
 * certificate checks, and every file is still checked against its pinned size
 * and sha256, so a proxy cannot change what is installed.
 *
 * Output names a proxy by host:port only. A proxy URL can carry a user name
 * and password; neither one, nor the URL that holds them, is written to any
 * output. Errors built here contain the host:port and a status or socket error
 * code, never the value of a variable.
 */

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';

/**
 * Variables read for an https:// model URL, in order. Lower case comes first
 * within each pair, as in curl, Node and undici. HTTP_PROXY is the fallback
 * for an https:// URL when no HTTPS_PROXY is set, as in npm and undici.
 */
const PROXY_VARIABLES = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'] as const;
const NO_PROXY_VARIABLES = ['no_proxy', 'NO_PROXY'] as const;

export interface ModelProxy {
  /** The variable the proxy came from, e.g. `HTTPS_PROXY`. */
  variable: string;
  /** host:port, the only form of the proxy that is ever printed. */
  display: string;
  protocol: 'http:' | 'https:';
  /** The host to connect to: an IPv6 literal without its brackets. */
  host: string;
  port: number;
  /** `Proxy-Authorization` value when the URL carries a user name or password. */
  authorization?: string;
}

export type ModelProxyRoute =
  | { kind: 'direct' }
  | { kind: 'proxy'; proxy: ModelProxy }
  /** A proxy variable is set but cannot be used. `reason` never repeats its value. */
  | { kind: 'unusable'; variable: string; reason: string };

type Env = Record<string, string | undefined>;

function firstSet(env: Env, names: readonly string[]): { name: string; value: string } | null {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return { name, value };
  }
  return null;
}

function decode(part: string): string {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

/**
 * True when NO_PROXY covers `host` on `port`. An entry matches the host and
 * every name under it, with or without a leading `.` or `*.`; `*` matches
 * every host; an entry with `:port` matches that port only.
 */
export function noProxyCovers(host: string, port: number, noProxy: string): boolean {
  const target = host.toLowerCase().replace(/\.$/, '');
  for (const raw of noProxy.split(/[\s,]+/)) {
    let entry = raw.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;
    const withPort = /^(.*[^:]):(\d+)$/.exec(entry);
    if (withPort && !withPort[1].includes(':')) {
      if (Number(withPort[2]) !== port) continue;
      entry = withPort[1];
    }
    entry = entry.replace(/^\*/, '').replace(/^\.+/, '').replace(/\.$/, '');
    if (!entry) continue;
    if (target === entry || target.endsWith(`.${entry}`)) return true;
  }
  return false;
}

/**
 * The proxy a request to `targetUrl` goes through, read from `env`.
 * NO_PROXY is checked first, so a host it covers goes direct even when the
 * proxy variable cannot be parsed.
 */
export function resolveModelProxy(targetUrl: string, env: Env = process.env): ModelProxyRoute {
  const target = new URL(targetUrl);
  const targetPort = Number(target.port) || (target.protocol === 'https:' ? 443 : 80);
  const setting = firstSet(env, PROXY_VARIABLES);
  if (!setting) return { kind: 'direct' };
  const noProxy = firstSet(env, NO_PROXY_VARIABLES);
  if (noProxy && noProxyCovers(target.hostname, targetPort, noProxy.value)) return { kind: 'direct' };

  const variable = setting.name;
  // `proxy.example.com:3128` with no scheme is common in these variables and
  // means an http:// proxy.
  const text = setting.value.includes('://') ? setting.value : `http://${setting.value}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { kind: 'unusable', variable, reason: 'is not a valid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    const scheme = /^[a-z][a-z0-9+.-]*:$/i.test(url.protocol) ? url.protocol.slice(0, -1) : 'another';
    return {
      kind: 'unusable',
      variable,
      reason: `names a ${scheme} proxy; the model download reaches a proxy only over http:// or https://`,
    };
  }
  if (!url.hostname) return { kind: 'unusable', variable, reason: 'names no proxy host' };

  const protocol = url.protocol;
  const port = Number(url.port) || (protocol === 'https:' ? 443 : 80);
  const proxy: ModelProxy = {
    variable,
    display: `${url.hostname}:${port}`,
    protocol,
    host: url.hostname.replace(/^\[(.*)\]$/, '$1'),
    port,
  };
  if (url.username || url.password) {
    const credentials = `${decode(url.username)}:${decode(url.password)}`;
    proxy.authorization = `Basic ${Buffer.from(credentials, 'utf8').toString('base64')}`;
  }
  return { kind: 'proxy', proxy };
}

/**
 * Open a TLS connection to `host:port` through a CONNECT tunnel on `proxy`.
 * The callback receives the TLS socket before its handshake completes; the
 * HTTP client writes the request once it does.
 *
 * `idleTimeoutMs`, when given, is how long the proxy may stay silent before
 * the tunnel request is abandoned, connecting included. The same bound is
 * then set on the TLS socket, where the HTTP client reports it as the
 * request's `timeout` event: a socket handed over by `createConnection` gets
 * no timeout from the client's own `timeout` option.
 */
export function connectThroughProxy(
  proxy: ModelProxy,
  host: string,
  port: number,
  idleTimeoutMs: number | undefined,
  callback: (err: Error | null, socket?: Duplex) => void,
): void {
  let settled = false;
  const finish = (err: Error | null, socket?: Duplex) => {
    if (settled) return;
    settled = true;
    callback(err, socket);
  };
  const authority = `${host}:${port}`;
  const headers: Record<string, string> = { host: authority };
  if (proxy.authorization) headers['proxy-authorization'] = proxy.authorization;
  const request = (proxy.protocol === 'https:' ? https : http).request({
    host: proxy.host,
    port: proxy.port,
    method: 'CONNECT',
    path: authority,
    headers,
    agent: false,
    ...(idleTimeoutMs ? { timeout: idleTimeoutMs } : {}),
  });
  request.once('connect', (response, socket) => {
    // The tunnel request's bound ends with its answer.
    socket.setTimeout(0);
    if (response.statusCode !== 200) {
      socket.destroy();
      finish(new Error(`proxy ${proxy.display} answered the tunnel request with HTTP ${response.statusCode}`));
      return;
    }
    const secure = tls.connect({ socket, servername: host });
    if (idleTimeoutMs) secure.setTimeout(idleTimeoutMs);
    finish(null, secure);
  });
  request.on('timeout', () => {
    request.destroy(new Error(`no answer to the tunnel request for ${(idleTimeoutMs ?? 0) / 1000}s`));
  });
  request.on('error', (err: NodeJS.ErrnoException) => {
    finish(new Error(`proxy ${proxy.display}: ${err.code ?? err.message}`));
  });
  request.end();
}

/**
 * Options for `https.get(targetUrl, options, callback)` that send the request
 * through `proxy`. `idleTimeoutMs`, when given, bounds a silent proxy and a
 * silent connection inside the tunnel alike; the caller ends the request on
 * its `timeout` event.
 */
export function proxiedRequestOptions(
  proxy: ModelProxy,
  targetUrl: string,
  idleTimeoutMs?: number,
): https.RequestOptions {
  const target = new URL(targetUrl);
  const port = Number(target.port) || 443;
  return {
    ...(idleTimeoutMs ? { timeout: idleTimeoutMs } : {}),
    // With no agent the client takes 80 as the default port and would send
    // `Host: huggingface.co:80`.
    defaultPort: 443,
    createConnection: (_options, oncreate) => {
      connectThroughProxy(proxy, target.hostname, port, idleTimeoutMs, (err, socket) => {
        // Node's own connection paths pass only the error on failure.
        if (err || !socket) (oncreate as (err: Error) => void)(err ?? new Error(`proxy ${proxy.display}: no socket`));
        else oncreate(null, socket);
      });
      return undefined;
    },
  };
}
