/**
 * #448 — a 200 is not an exposed file.
 *
 * `scan` reported CONFIG-EXPOSED for every config path and CLAUDE-MD-EXPOSED
 * for /CLAUDE.md on any host that answers 200 on every path, which is the
 * default for an SPA with a catch-all route. Measured before the fix against a
 * server answering `{"id":"x"}` everywhere: 6 CRITICAL + 1 HIGH, none real.
 * And a real dotenv served as text/plain was missed, because the check only
 * accepted a JSON body.
 *
 * Each port is now also asked for a path that cannot exist; a 200 counts only
 * when its body differs from that answer and has the shape of the file.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { ExternalScanner } from '../../src/scanner/external-scanner';
import * as http from 'http';
import type { AddressInfo } from 'net';

const EXPOSURE = ['CONFIG-EXPOSED', 'CLAUDE-MD-EXPOSED'];

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port };
}

describe('ExternalScanner config and CLAUDE.md exposure against catch-all hosts', () => {
  const scanner = new ExternalScanner();
  const servers: http.Server[] = [];
  afterEach(async () => {
    for (const s of servers.splice(0)) await new Promise<void>((r) => s.close(() => r()));
  });

  async function scan(handler: http.RequestListener) {
    const { server, port } = await listen(handler);
    servers.push(server);
    const result = await scanner.scan('127.0.0.1', { ports: [port], timeout: 2000 });
    return { result, port, exposures: result.findings.filter((f) => EXPOSURE.includes(f.checkId)) };
  }

  it('the issue reproduction: the same JSON body on every path yields zero exposure findings', async () => {
    const { result, exposures } = await scan((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"id":"x"}');
    });
    expect(exposures).toEqual([]);
    expect(result.score).toBe(100);
  });

  it('a catch-all that echoes the requested path yields zero exposure findings', async () => {
    const { exposures } = await scan((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'no route', path: req.url }));
    });
    expect(exposures).toEqual([]);
  });

  it('a catch-all whose values vary per request, with the same keys, yields zero exposure findings', async () => {
    let n = 0;
    const { exposures } = await scan((_req, res) => {
      n += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ requestId: `r-${n}`, at: Date.now() + n }));
    });
    expect(exposures).toEqual([]);
  });

  it('a plain-text catch-all yields no CLAUDE-MD-EXPOSED and no dotenv finding', async () => {
    const { exposures } = await scan((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('OK');
    });
    expect(exposures).toEqual([]);
  });

  it('a real dotenv served as text/plain at its path, 404 elsewhere, is a CRITICAL CONFIG-EXPOSED with a curl verify', async () => {
    const { exposures, port } = await scan((req, res) => {
      if (req.url === '/.env') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('# app settings\n\nAPP_MODE=production\nLOG_LEVEL=debug\n');
        return;
      }
      res.writeHead(404);
      res.end('not found');
    });
    expect(exposures.map((f) => [f.checkId, f.path, f.severity])).toEqual([['CONFIG-EXPOSED', '/.env', 'critical']]);
    expect(exposures[0].verify).toBe(`curl -si http://127.0.0.1:${port}/.env`);
  });

  it('a real dotenv behind a JSON catch-all is still found, and only it', async () => {
    const { exposures } = await scan((req, res) => {
      if (req.url === '/.env') {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        res.end('APP_MODE=production\n');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"id":"x"}');
    });
    expect(exposures.map((f) => [f.checkId, f.path, f.severity])).toEqual([['CONFIG-EXPOSED', '/.env', 'critical']]);
  });

  it('a real mcp.json is a CRITICAL CONFIG-EXPOSED with a curl verify', async () => {
    const { exposures, port } = await scan((req, res) => {
      if (req.url === '/mcp.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ mcpServers: { files: { command: 'npx', args: ['server-files'] } } }));
        return;
      }
      res.writeHead(404);
      res.end('not found');
    });
    expect(exposures.map((f) => [f.checkId, f.path, f.severity])).toEqual([['CONFIG-EXPOSED', '/mcp.json', 'critical']]);
    expect(exposures[0].verify).toBe(`curl -si http://127.0.0.1:${port}/mcp.json`);
  });

  it('a JSON object at an mcp.json path without mcpServers or servers is not an MCP config', async () => {
    const { exposures } = await scan((req, res) => {
      if (req.url === '/mcp.json' || req.url === '/.vscode/mcp.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ name: 'docs page', version: 2 }));
        return;
      }
      res.writeHead(404);
      res.end('not found');
    });
    expect(exposures).toEqual([]);
  });

  it('a dotenv path answering an HTML page is not a dotenv file', async () => {
    const { exposures } = await scan((req, res) => {
      if (req.url === '/.env') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<!DOCTYPE html><html><body>APP=1</body></html>');
        return;
      }
      res.writeHead(404);
      res.end('not found');
    });
    expect(exposures).toEqual([]);
  });

  it('a CLAUDE.md that differs from the catch-all answer is still a HIGH with a curl verify', async () => {
    const { exposures, port } = await scan((req, res) => {
      if (req.url === '/CLAUDE.md') {
        res.writeHead(200, { 'content-type': 'text/markdown' });
        res.end('# Agent instructions\n\nAlways answer in French.\n');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('OK');
    });
    expect(exposures.map((f) => [f.checkId, f.path, f.severity])).toEqual([['CLAUDE-MD-EXPOSED', '/CLAUDE.md', 'high']]);
    expect(exposures[0].verify).toBe(`curl -si http://127.0.0.1:${port}/CLAUDE.md`);
  });
});
