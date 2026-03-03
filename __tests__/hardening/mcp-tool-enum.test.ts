import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

import {
  discoverMcpConfigs,
  classifyTools,
  checkMcpToolEnumeration,
  type McpToolInfo,
} from '../../src/hardening/mcp-tool-enum';

describe('MCP Tool Enumeration', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-mcp-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('discoverMcpConfigs', () => {
    it('discovers mcp.json in target directory', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'test-server': { command: 'node', args: ['server.js'] },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.size).toBe(1);
      expect(configs.has('test-server')).toBe(true);
      const entry = configs.get('test-server')!;
      expect(entry.config.command).toBe('node');
      expect(entry.config.args).toEqual(['server.js']);
      expect(entry.configPath).toBe(path.join(tempDir, 'mcp.json'));
    });

    it('discovers .cursor/mcp.json', async () => {
      await fs.mkdir(path.join(tempDir, '.cursor'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, '.cursor', 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'cursor-server': { command: 'npx', args: ['-y', 'some-mcp'] },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.has('cursor-server')).toBe(true);
    });

    it('discovers .vscode/mcp.json', async () => {
      await fs.mkdir(path.join(tempDir, '.vscode'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, '.vscode', 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'vscode-server': { command: 'node', args: ['mcp.js'] },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.has('vscode-server')).toBe(true);
    });

    it('handles missing config files gracefully', async () => {
      const configs = await discoverMcpConfigs(tempDir);
      // Should not throw; may find global configs from homedir
      expect(configs).toBeInstanceOf(Map);
    });

    it('handles invalid JSON gracefully', async () => {
      await fs.writeFile(path.join(tempDir, 'mcp.json'), 'not valid json {{{');
      const configs = await discoverMcpConfigs(tempDir);
      // Should not throw, just skip invalid file
      expect(configs).toBeInstanceOf(Map);
    });

    it('parses servers with env vars', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'env-server': {
              command: 'node',
              args: ['server.js'],
              env: { API_KEY: 'test123' },
            },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.get('env-server')?.config.env).toEqual({ API_KEY: 'test123' });
    });

    it('parses servers with url field', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'sse-server': { url: 'http://localhost:3000/sse' },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.has('sse-server')).toBe(true);
      expect(configs.get('sse-server')?.config.url).toBe('http://localhost:3000/sse');
    });

    it('supports alternative "servers" key', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          servers: {
            'alt-server': { command: 'python', args: ['server.py'] },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.has('alt-server')).toBe(true);
    });

    it('merges configs from multiple locations', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'root-server': { command: 'node', args: ['root.js'] },
          },
        }),
      );
      await fs.mkdir(path.join(tempDir, '.cursor'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, '.cursor', 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'cursor-server': { command: 'node', args: ['cursor.js'] },
          },
        }),
      );
      const configs = await discoverMcpConfigs(tempDir);
      expect(configs.has('root-server')).toBe(true);
      expect(configs.has('cursor-server')).toBe(true);
    });
  });

  describe('classifyTools', () => {
    it('MCPTOOL-001: detects execution tools', () => {
      const tools: McpToolInfo[] = [
        { name: 'execute_command', description: 'Run a command' },
        { name: 'read_file', description: 'Read a file' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      const exec = findings.find((f) => f.checkId === 'MCPTOOL-001');
      expect(exec).toBeDefined();
      expect(exec!.severity).toBe('critical');
      expect(exec!.passed).toBe(false);
      expect(exec!.category).toBe('mcp-capability');
    });

    it('MCPTOOL-001: detects all execution tool variants', () => {
      const execNames = ['bash', 'shell', 'exec', 'run', 'system', 'subprocess'];
      for (const name of execNames) {
        const findings = classifyTools('test', 'mcp.json', [{ name }]);
        const exec = findings.find((f) => f.checkId === 'MCPTOOL-001');
        expect(exec).toBeDefined();
      }
    });

    it('MCPTOOL-002: detects filesystem write tools', () => {
      const tools: McpToolInfo[] = [
        { name: 'write_file', description: 'Write a file' },
        { name: 'delete_file', description: 'Delete a file' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      const fsFind = findings.find((f) => f.checkId === 'MCPTOOL-002');
      expect(fsFind).toBeDefined();
      expect(fsFind!.severity).toBe('high');
      expect(fsFind!.message).toContain('2 filesystem write tool(s)');
    });

    it('MCPTOOL-003: detects network tools', () => {
      const tools: McpToolInfo[] = [
        { name: 'fetch', description: 'Make HTTP request' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      const net = findings.find((f) => f.checkId === 'MCPTOOL-003');
      expect(net).toBeDefined();
      expect(net!.severity).toBe('high');
    });

    it('MCPTOOL-004: detects credential access tools', () => {
      const tools: McpToolInfo[] = [
        { name: 'get_secret', description: 'Get secret' },
        { name: 'read_env', description: 'Read env var' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      const cred = findings.find((f) => f.checkId === 'MCPTOOL-004');
      expect(cred).toBeDefined();
      expect(cred!.severity).toBe('critical');
      expect(cred!.fix).toContain('secretless-ai');
    });

    it('MCPTOOL-005: detects excessive tool count', () => {
      const tools: McpToolInfo[] = Array.from({ length: 12 }, (_, i) => ({
        name: `safe_tool_${i}`,
        description: `Tool ${i}`,
      }));
      const findings = classifyTools('test', 'mcp.json', tools);
      const excessive = findings.find((f) => f.checkId === 'MCPTOOL-005');
      expect(excessive).toBeDefined();
      expect(excessive!.severity).toBe('medium');
      expect(excessive!.message).toContain('12 tools exposed');
    });

    it('MCPTOOL-005: does not trigger below threshold', () => {
      const tools: McpToolInfo[] = Array.from({ length: 9 }, (_, i) => ({
        name: `safe_tool_${i}`,
      }));
      const findings = classifyTools('test', 'mcp.json', tools);
      const excessive = findings.find((f) => f.checkId === 'MCPTOOL-005');
      expect(excessive).toBeUndefined();
    });

    it('no findings for safe tools', () => {
      const tools: McpToolInfo[] = [
        { name: 'read_file', description: 'Read a file' },
        { name: 'search', description: 'Search content' },
        { name: 'list_files', description: 'List files' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      expect(findings.length).toBe(0);
    });

    it('handles empty tool list', () => {
      const findings = classifyTools('test', 'mcp.json', []);
      expect(findings.length).toBe(0);
    });

    it('detects multiple categories simultaneously', () => {
      const tools: McpToolInfo[] = [
        { name: 'bash' },
        { name: 'write_file' },
        { name: 'fetch' },
        { name: 'get_secret' },
        ...Array.from({ length: 8 }, (_, i) => ({ name: `util_${i}` })),
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      const checkIds = new Set(findings.map((f) => f.checkId));
      expect(checkIds.has('MCPTOOL-001')).toBe(true);
      expect(checkIds.has('MCPTOOL-002')).toBe(true);
      expect(checkIds.has('MCPTOOL-003')).toBe(true);
      expect(checkIds.has('MCPTOOL-004')).toBe(true);
      expect(checkIds.has('MCPTOOL-005')).toBe(true);
    });

    it('case-insensitive tool name matching', () => {
      const tools: McpToolInfo[] = [{ name: 'Execute_Command' }];
      const findings = classifyTools('test', 'mcp.json', tools);
      expect(findings.find((f) => f.checkId === 'MCPTOOL-001')).toBeDefined();
    });

    it('includes server name in finding description', () => {
      const tools: McpToolInfo[] = [{ name: 'bash' }];
      const findings = classifyTools('my-mcp-server', 'mcp.json', tools);
      expect(findings[0].description).toContain('my-mcp-server');
    });

    it('includes config path as file in findings', () => {
      const tools: McpToolInfo[] = [{ name: 'bash' }];
      const findings = classifyTools('test', '/path/to/mcp.json', tools);
      expect(findings[0].file).toBe('/path/to/mcp.json');
    });

    it('all findings have fixable=false', () => {
      const tools: McpToolInfo[] = [
        { name: 'bash' },
        { name: 'write_file' },
        { name: 'fetch' },
        { name: 'get_secret' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      for (const f of findings) {
        expect(f.fixable).toBe(false);
      }
    });

    it('all findings have passed=false', () => {
      const tools: McpToolInfo[] = [
        { name: 'bash' },
        { name: 'write_file' },
      ];
      const findings = classifyTools('test', 'mcp.json', tools);
      for (const f of findings) {
        expect(f.passed).toBe(false);
      }
    });
  });

  describe('checkMcpToolEnumeration', () => {
    it('returns empty findings when no MCP configs found', async () => {
      const findings = await checkMcpToolEnumeration(tempDir);
      expect(findings).toBeInstanceOf(Array);
      expect(findings.length).toBe(0);
    });

    it('calls progress callback when configs are found', async () => {
      // Create a config pointing to a non-existent command so it errors out
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'broken-server': { command: 'nonexistent-binary-xyz', args: [] },
          },
        }),
      );
      const progress = vi.fn();
      await checkMcpToolEnumeration(tempDir, progress);
      // Should have been called at least once for "Found N MCP server(s)"
      expect(progress).toHaveBeenCalled();
      const messages = progress.mock.calls.map((c: string[]) => c[0]);
      expect(messages.some((m: string) => m.includes('1 MCP server(s)'))).toBe(true);
    });

    it('handles spawn errors gracefully', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'bad-server': { command: 'this-command-does-not-exist-at-all', args: [] },
          },
        }),
      );
      // Should not throw
      const findings = await checkMcpToolEnumeration(tempDir);
      expect(findings).toBeInstanceOf(Array);
    });

    it('skips servers with only url (no command)', async () => {
      await fs.writeFile(
        path.join(tempDir, 'mcp.json'),
        JSON.stringify({
          mcpServers: {
            'sse-only': { url: 'http://localhost:3000/sse' },
          },
        }),
      );
      const findings = await checkMcpToolEnumeration(tempDir);
      // SSE not implemented yet, should skip without error
      expect(findings).toBeInstanceOf(Array);
      expect(findings.length).toBe(0);
    });
  });
});
