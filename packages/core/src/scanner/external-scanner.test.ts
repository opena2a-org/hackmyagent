import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ExternalScanner } from './external-scanner';
import type { ExternalScanResult } from './types';
import * as http from 'http';
import type { AddressInfo } from 'net';

describe('ExternalScanner', () => {
  let scanner: ExternalScanner;

  beforeEach(() => {
    scanner = new ExternalScanner();
  });

  describe('scan', () => {
    it('returns a scan result with required fields', async () => {
      const result = await scanner.scan('localhost', {
        timeout: 1000,
        skipPortScan: true,
      });

      expect(result).toMatchObject({
        id: expect.any(String),
        target: 'localhost',
        score: expect.any(Number),
        grade: expect.any(String),
        findings: expect.any(Array),
        duration: expect.any(Number),
        timestamp: expect.any(Date),
        openPorts: expect.any(Array),
      });
    });

    it('calculates grade based on score', async () => {
      const result = await scanner.scan('localhost', { skipPortScan: true });

      // Grade should be A-F based on score
      expect(['A', 'B', 'C', 'D', 'F']).toContain(result.grade);
    });

    it('returns duration in milliseconds', async () => {
      const result = await scanner.scan('localhost', {
        timeout: 1000,
        skipPortScan: true,
      });

      expect(result.duration).toBeGreaterThanOrEqual(0);
      expect(result.duration).toBeLessThan(30000);
    });
  });

  describe('port scanning', () => {
    let server: http.Server;
    let port: number;

    beforeEach(async () => {
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('detects open ports', async () => {
      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 2000,
      });

      expect(result.openPorts).toContain(port);
    });

    it('does not report closed ports', async () => {
      // Use a port that's likely closed but within valid range (1-65535)
      // Pick port+1 if port < 65000, otherwise port-1000 to stay within range
      const closedPort = port < 65000 ? port + 1 : port - 1000;
      const result = await scanner.scan('127.0.0.1', {
        ports: [closedPort],
        timeout: 1000,
      });

      expect(result.openPorts).not.toContain(closedPort);
    });
  });

  describe('security checks', () => {
    let server: http.Server;
    let port: number;

    afterEach(async () => {
      if (server) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });

    it('detects exposed MCP SSE endpoint', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/sse' || req.url === '/mcp/sse') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream' });
          res.end('data: test\n\n');
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const sseFinding = result.findings.find((f) => f.checkId === 'MCP-SSE');
      expect(sseFinding).toBeDefined();
      expect(sseFinding?.severity).toBe('critical');
    });

    it('detects exposed MCP tools endpoint', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/tools' || req.url === '/mcp/tools') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ tools: [{ name: 'test' }] }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const toolsFinding = result.findings.find((f) => f.checkId === 'MCP-TOOLS');
      expect(toolsFinding).toBeDefined();
      expect(toolsFinding?.severity).toBe('critical');
    });

    it('detects exposed config files', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/.claude/settings.json') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ settings: true }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const configFinding = result.findings.find((f) => f.checkId === 'CONFIG-EXPOSED');
      expect(configFinding).toBeDefined();
      expect(configFinding?.severity).toBe('critical');
    });

    it('detects exposed CLAUDE.md', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/CLAUDE.md') {
          res.writeHead(200, { 'Content-Type': 'text/markdown' });
          res.end('# System Instructions\n\nYou are a helpful assistant.');
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const claudeFinding = result.findings.find((f) => f.checkId === 'CLAUDE-MD-EXPOSED');
      expect(claudeFinding).toBeDefined();
      expect(claudeFinding?.severity).toBe('high');
    });

    it('detects exposed API keys in responses', async () => {
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          config: {
            apiKey: 'sk-ant-api03-realkey1234567890abcdef',
          },
        }));
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const apiKeyFinding = result.findings.find((f) => f.checkId === 'API-KEY-EXPOSED');
      expect(apiKeyFinding).toBeDefined();
      expect(apiKeyFinding?.severity).toBe('critical');
    });

    it('detects VSCode MCP config exposure', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/.vscode/mcp.json') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ servers: {} }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const configFinding = result.findings.find(
        (f) => f.checkId === 'CONFIG-EXPOSED' && f.path?.includes('.vscode')
      );
      expect(configFinding).toBeDefined();
    });

    it('detects Cursor MCP config exposure', async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/.cursor/mcp.json') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ servers: {} }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      const configFinding = result.findings.find(
        (f) => f.checkId === 'CONFIG-EXPOSED' && f.path?.includes('.cursor')
      );
      expect(configFinding).toBeDefined();
    });
  });

  describe('score calculation', () => {
    it('returns 100 for target with no findings', async () => {
      const result = await scanner.scan('localhost', { skipPortScan: true });

      // With no accessible ports, should have no findings
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
    });

    it('deducts points for critical findings', async () => {
      let server: http.Server;
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.end('data: test\n\n');
      });
      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
      });
      const port = (server.address() as AddressInfo).port;

      const result = await scanner.scan('127.0.0.1', {
        ports: [port],
        timeout: 5000,
      });

      // Critical finding should reduce score
      expect(result.score).toBeLessThan(100);

      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
  });
});
