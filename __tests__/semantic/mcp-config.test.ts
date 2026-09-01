import { describe, it, expect } from 'vitest';
import { McpConfigAnalyzer } from '../../src/semantic/structural/mcp-config';
import type { AnalysisFile } from '../../src/semantic/types';

const analyzer = new McpConfigAnalyzer();

function makeMcpFile(content: string, path = 'mcp.json'): AnalysisFile {
  return { path, type: 'mcp_config', content, truncated: false };
}

describe('McpConfigAnalyzer', () => {
  describe('overprivileged scope', () => {
    it('detects root filesystem access', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          fs: { command: 'npx', args: ['-y', 'server-filesystem', '/'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-001' && f.severity === 'critical')).toBe(true);
    });

    it('detects /Users directory access', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          fs: { command: 'npx', args: ['-y', 'server-filesystem', '/Users'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-001')).toBe(true);
    });

    it('detects home directory access', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          fs: { command: 'npx', args: ['-y', 'server-filesystem', '/home'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-001')).toBe(true);
    });

    it('does not flag project-scoped paths', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          fs: { command: 'npx', args: ['-y', 'server-filesystem', './data'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-MCP-001')).toHaveLength(0);
    });
  });

  describe('sandbox bypass', () => {
    it('detects --no-sandbox flag', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          browser: { command: 'npx', args: ['puppeteer-server', '--no-sandbox'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-002')).toBe(true);
    });

    it('detects --privileged flag', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          docker: { command: 'docker', args: ['run', '--privileged', 'mcp-server'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-002')).toBe(true);
    });
  });

  describe('secrets in args', () => {
    it('detects GitHub token in args', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          github: { command: 'npx', args: ['server-github', '--token', ['ghp', '_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'].join('')] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-003')).toBe(true);
    });

    it('detects API key pattern directly in args', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          api: { command: 'node', args: ['server.js', ['sk', '-ant-api03-someLongKeyValueHere12345'].join('')] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-003')).toBe(true);
    });
  });

  describe('wildcard permissions', () => {
    it('detects allowedTools wildcard', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          myserver: { command: 'node', args: ['server.js'], allowedTools: ['*'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-004')).toBe(true);
    });
  });

  describe('attack chains', () => {
    it('detects filesystem + shell + network chain', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          filesystem: { command: 'npx', args: ['server-filesystem', './'] },
          shell: { command: 'npx', args: ['mcp-shell-server'] },
          'http-fetch': { command: 'npx', args: ['mcp-http-fetch-server'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-005' && f.severity === 'high')).toBe(true);
    });

    it('detects filesystem + network chain', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: {
          filesystem: { command: 'npx', args: ['server-filesystem', './'] },
          fetch: { command: 'npx', args: ['mcp-fetch-server'] },
        },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-005' && f.description.includes('read-exfiltrate'))).toBe(true);
    });
  });

  describe('server count', () => {
    it('flags more than 5 servers', () => {
      const servers: Record<string, { command: string; args: string[] }> = {};
      for (let i = 0; i < 6; i++) {
        servers[`server${i}`] = { command: 'npx', args: [`server-${i}`] };
      }
      const file = makeMcpFile(JSON.stringify({ mcpServers: servers }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-MCP-006')).toBe(true);
    });
  });
});
