/**
 * HMA-71 — the Layer-2 MCP analyzer does not go blind on the file `init-mcp`
 * now writes for VS Code.
 *
 * `analyze` read `config.mcpServers || {}` and nothing else, so an
 * `.vscode/mcp.json` — whose top-level key is `servers` — contributed an empty
 * server map: no overprivileged scope, no sandbox bypass, no secret in args, no
 * attack chain, and a server count of zero. Layer 1's VSCODE-002 saw the file;
 * Layer 2 saw an empty one.
 */

import { describe, it, expect } from 'vitest';
import { McpConfigAnalyzer } from '../../src/semantic/structural/mcp-config';
import type { AnalysisFile, SemanticFinding } from '../../src/semantic/types';

const analyzer = new McpConfigAnalyzer();

function makeMcpFile(content: string, path = '.vscode/mcp.json'): AnalysisFile {
  return { path, type: 'mcp_config', content, truncated: false };
}

/** The comparable shape of a finding set: id, severity and line, order-free. */
function shape(findings: SemanticFinding[]): string[] {
  return findings.map((f) => `${f.id}|${f.severity}|${f.line ?? '-'}`).sort();
}

const FILESYSTEM_AT_ROOT = {
  filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
};

describe('HMA-71.AC5: a servers-keyed MCP config is analyzed like an mcpServers-keyed one', () => {
  it('HMA-71.AC5 servers yields the same finding ids, severities and lines as mcpServers', () => {
    const asServers = analyzer.analyze([makeMcpFile(JSON.stringify({ servers: FILESYSTEM_AT_ROOT }))]);
    const asMcpServers = analyzer.analyze([makeMcpFile(JSON.stringify({ mcpServers: FILESYSTEM_AT_ROOT }))]);

    expect(shape(asServers)).toEqual(shape(asMcpServers));
    // Non-vacuity: the shared shape is not the empty set.
    expect(asServers.some((f) => f.id === 'SEM-MCP-001' && f.severity === 'critical')).toBe(true);
  });

  it('HMA-71.AC5 the line a finding points at is the same under either key', () => {
    // Pretty-printed, so `line` is a real position rather than 1 for everything:
    // swapping the key name changes one line's text, never the line count.
    const pretty = (key: string) =>
      analyzer.analyze([makeMcpFile(JSON.stringify({ [key]: FILESYSTEM_AT_ROOT }, null, 2))]);

    expect(shape(pretty('servers'))).toEqual(shape(pretty('mcpServers')));
    expect(pretty('servers').find((f) => f.id === 'SEM-MCP-001')?.line).toBeGreaterThan(1);
  });

  it('HMA-71.AC5 a file carrying both keys yields the union of its servers', () => {
    const both = analyzer.analyze([
      makeMcpFile(
        JSON.stringify({
          mcpServers: { filesystem: { command: 'npx', args: ['server-filesystem', './'] } },
          servers: {
            shell: { command: 'npx', args: ['mcp-shell-server'] },
            'http-fetch': { command: 'npx', args: ['mcp-http-fetch-server'] },
          },
        }),
      ),
    ]);

    // filesystem + shell + network is the read-execute-exfiltrate chain, and it
    // is only reachable if BOTH keys contributed their servers.
    expect(both.some((f) => f.id === 'SEM-MCP-005' && f.title.includes('read-execute-exfiltrate'))).toBe(true);
  });

  it('HMA-71.AC5 one server name under both keys is not evaluated twice', () => {
    const duplicated = analyzer.analyze([
      makeMcpFile(JSON.stringify({ mcpServers: FILESYSTEM_AT_ROOT, servers: FILESYSTEM_AT_ROOT })),
    ]);
    const once = analyzer.analyze([makeMcpFile(JSON.stringify({ mcpServers: FILESYSTEM_AT_ROOT }))]);

    expect(shape(duplicated)).toEqual(shape(once));
  });
});
