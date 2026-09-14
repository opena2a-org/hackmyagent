/**
 * `scan <target>` reachability (advertised-command audit 2026-09-13, lane F).
 *
 * Measured on 0.33.0 against a live site answering 443:
 *   - `scan https://opena2a.org`  -> Score -1/100, SCAN-UNREACHABLE in 34 ms. The
 *     raw string "https://opena2a.org" was handed to `socket.connect` as the
 *     DNS name, so every port "failed" before a packet left the machine.
 *   - `scan opena2a.org`          -> "Scan timed out after 4000ms". Both ports
 *     opened, then the per-port HTTP probes (17 sequential requests per port)
 *     ran against a global budget of ports x timeout that never included them.
 *
 * Three states must be told apart, in the tool's own words: unreachable (the
 * name does not resolve, or nothing answers), reachable with no open port among
 * those scanned (something answered, nothing to test), and reachable with open
 * ports (a real score).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { ExternalScanner, DEFAULT_PORTS } from '../../src/scanner/external-scanner';
import * as http from 'http';
import * as net from 'net';
import type { AddressInfo } from 'net';

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port };
}

async function closedPort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

describe('ExternalScanner reachability', () => {
  const scanner = new ExternalScanner();
  const servers: http.Server[] = [];
  afterEach(async () => {
    for (const s of servers.splice(0)) await new Promise<void>((r) => s.close(() => r()));
  });

  it('exports the default port list the CLI prints', () => {
    expect(DEFAULT_PORTS).toEqual([80, 443]);
  });

  it('a URL target is scanned by hostname, and its port when it names one', async () => {
    const { server, port } = await listen((_req, res) => { res.writeHead(200); res.end('ok'); });
    servers.push(server);

    const result = await scanner.scan(`http://127.0.0.1:${port}`, { timeout: 1000 });

    expect(result.openPorts).toEqual([port]);
    expect(result.hostReachable).toBe(true);
    expect(result.score).not.toBe(-1);
    expect(result.findings.map((f) => f.checkId)).not.toContain('SCAN-UNREACHABLE');
  });

  it('a schemeless host with a path scans the host, as before', async () => {
    const { server, port } = await listen((_req, res) => { res.writeHead(200); res.end('ok'); });
    servers.push(server);

    const result = await scanner.scan(`127.0.0.1:${port}/status`, { timeout: 1000 });

    expect(result.openPorts).toEqual([port]);
    expect(result.hostReachable).toBe(true);
  });

  it('a URL target without a port keeps the default port list, on the parsed hostname', async () => {
    const { server, port } = await listen((_req, res) => { res.writeHead(200); res.end('ok'); });
    servers.push(server);

    // `-p` still wins over the URL's default; the hostname must be parsed out
    // of the scheme either way.
    const result = await scanner.scan('https://127.0.0.1', { ports: [port], timeout: 1000 });

    expect(result.openPorts).toEqual([port]);
    expect(result.hostReachable).toBe(true);
  });

  it('a host that answers with a refusal is reachable with no open ports, not unreachable', async () => {
    const port = await closedPort();

    const result = await scanner.scan('127.0.0.1', { ports: [port], timeout: 1000 });

    expect(result.openPorts).toEqual([]);
    expect(result.hostReachable).toBe(true);
    expect(result.portStates).toEqual({ [port]: 'closed' });
    expect(result.score).toBe(-1);
    expect(result.grade).toBe('N/A');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].checkId).toBe('SCAN-NO-OPEN-PORTS');
    expect(result.findings[0].title).toMatch(/reachable/i);
    expect(result.findings[0].title).not.toMatch(/unreachable/i);
  });

  it('a name that does not resolve is unreachable, and says so', async () => {
    const result = await scanner.scan('scan-reachability.invalid', { ports: [80], timeout: 1000 });

    expect(result.openPorts).toEqual([]);
    expect(result.hostReachable).toBe(false);
    expect(result.portStates).toEqual({ 80: 'unresolved' });
    expect(result.score).toBe(-1);
    expect(result.findings[0].checkId).toBe('SCAN-UNREACHABLE');
    expect(result.findings[0].description).toMatch(/did not resolve/i);
  });

  it('an address that never answers is unreachable, and the scan ends inside the budget', async () => {
    // RFC 5737 TEST-NET-1: not routed, so the connect either times out or the
    // kernel reports no route; both mean nothing answered.
    const timeout = 300;
    const started = Date.now();
    const result = await scanner.scan('192.0.2.1', { ports: [80, 443], timeout });

    expect(result.hostReachable).toBe(false);
    expect(result.findings[0].checkId).toBe('SCAN-UNREACHABLE');
    expect(Object.values(result.portStates ?? {}).every((s) => s === 'filtered' || s === 'error')).toBe(true);
    // Port probes run concurrently and the reachability re-check adds at most
    // one more round; the old shape spent ports x timeout before giving up.
    expect(Date.now() - started).toBeLessThan(timeout * 4);
  });

  it('a page larger than the body cap answers at once instead of waiting out the probe deadline', async () => {
    // A destroyed response emits neither 'end' nor 'error'; 0.33.0 destroyed
    // at the cap and then waited for the deadline on every oversized page.
    const big = 'x'.repeat(40_000);
    const { server, port } = await listen((req, res) => {
      // Only the root page exists; a 200 on /CLAUDE.md would be a real finding.
      if (req.url !== '/') { res.writeHead(404); res.end('not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(big);
    });
    servers.push(server);
    const timeout = 2000;
    const started = Date.now();

    const result = await scanner.scan('127.0.0.1', { ports: [port], timeout });

    expect(result.openPorts).toEqual([port]);
    expect(result.score).toBe(100);
    // Seventeen probes, every one oversized: under the old shape this is
    // 6 x 2000 ms on the longest chain; answered at the cap it is well under one.
    expect(Date.now() - started).toBeLessThan(timeout);
  });

  it('an HTML page at /tools is not an MCP tools listing, a JSON one is', async () => {
    const html = '<!DOCTYPE html><html><body><h1>Our tools</h1><p>All the tools we ship.</p></body></html>';
    const { server, port } = await listen((req, res) => {
      if (req.url === '/tools') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html); return; }
      res.writeHead(404); res.end('not found');
    });
    servers.push(server);
    const { server: mcp, port: mcpPort } = await listen((req, res) => {
      if (req.url === '/tools') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ tools: [{ name: 'read_file' }] })); return; }
      res.writeHead(404); res.end('not found');
    });
    servers.push(mcp);

    const page = await scanner.scan('127.0.0.1', { ports: [port], timeout: 1000 });
    const listing = await scanner.scan('127.0.0.1', { ports: [mcpPort], timeout: 1000 });

    expect(page.findings.map((f) => f.checkId)).not.toContain('MCP-TOOLS');
    expect(page.score).toBe(100);
    expect(listing.findings.map((f) => f.checkId)).toContain('MCP-TOOLS');
  });

  it('an HTML fallback page at /CLAUDE.md is not an exposed CLAUDE.md, a markdown body is', async () => {
    const fallback = '<!DOCTYPE html><html><body>Single-page app shell</body></html>';
    const { server, port } = await listen((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(fallback); });
    servers.push(server);
    const { server: md, port: mdPort } = await listen((req, res) => {
      if (req.url === '/CLAUDE.md') { res.writeHead(200, { 'Content-Type': 'text/markdown' }); res.end('# Agent instructions\n\nAlways answer in French.\n'); return; }
      res.writeHead(404); res.end('not found');
    });
    servers.push(md);

    const spa = await scanner.scan('127.0.0.1', { ports: [port], timeout: 1000 });
    const exposed = await scanner.scan('127.0.0.1', { ports: [mdPort], timeout: 1000 });

    expect(spa.findings.map((f) => f.checkId)).not.toContain('CLAUDE-MD-EXPOSED');
    expect(exposed.findings.map((f) => f.checkId)).toContain('CLAUDE-MD-EXPOSED');
  });

  it('a host that opens the port but never answers HTTP completes with a score instead of timing out', async () => {
    // The 0.33.0 defect on a live site: the port scan succeeded, then the
    // sequential probes outran a budget that only counted the port scan.
    const { server, port } = await listen(() => { /* hold the request open */ });
    servers.push(server);
    const timeout = 200;
    const started = Date.now();

    const result = await scanner.scan('127.0.0.1', { ports: [port], timeout });

    expect(result.openPorts).toEqual([port]);
    expect(result.hostReachable).toBe(true);
    expect(result.score).toBe(100);
    expect(result.findings).toEqual([]);
    // Probe categories run concurrently per port; the longest chain is six
    // requests, each bounded by `timeout` end to end, not only when idle.
    expect(Date.now() - started).toBeLessThan(timeout * 9);
  });
});
