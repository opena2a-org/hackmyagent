/**
 * #669 — the server-walking MCP, NET and TOOL checks read every server map key
 * through `mcpServerEntries`, so a `mcpServers` file now reaches MCP-005,
 * MCP-008 and NET-002, and TOOL-001 names its servers. Two of those reads took
 * a parsed value on trust:
 *   - MCP-005 called `allowedTools.includes`, and NET-002 and MCP-008 called
 *     `url.startsWith` / `url.includes`, on any truthy value. A server entry is
 *     parsed JSON, so `"allowedTools": 5` or `"url": 7` threw, the coverage
 *     ledger rethrew, and the scan of the whole tree ended with no report. Each
 *     test now runs only on a value of the type it needs; any other value
 *     declares nothing, and the rest of the file and the tree are still read.
 *   - TOOL-001's failure quotes server names as they appear in the file. A
 *     name is file content on its way to a terminal, so it is escaped for
 *     display and capped at 60 characters.
 */
import { describe, it, expect } from 'vitest';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { MCP_SERVER_MAP_KEYS } from '../../src/mcp-clients';
import { tempDir } from '../helpers/temp-dir';

interface Record_ {
  checkId: string;
  passed?: boolean;
  message?: string;
}

const ROOT_MCP_CHECK = /^(MCP-00[1-9]|MCP-010|TOOL-00[1-3]|NET-00[12])$/;

async function scanConfig(config: unknown): Promise<Record_[]> {
  const dir = tempDir('hma669-shape-');
  writeFileSync(path.join(dir, 'mcp.json'), JSON.stringify(config));
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
  return ((result as unknown as { allFindings: Record_[] }).allFindings).filter((f) => ROOT_MCP_CHECK.test(f.checkId));
}

function record(records: Record_[], checkId: string): Record_ | undefined {
  return records.find((r) => r.checkId === checkId);
}

function failed(records: Record_[], checkId: string): boolean {
  return records.some((r) => r.checkId === checkId && r.passed === false);
}

describe('a server value of the wrong type declares nothing and does not end the scan (#669)', { timeout: 120_000 }, () => {
  for (const key of MCP_SERVER_MAP_KEYS) {
    for (const [label, allowedTools] of [['a number', 5], ['an object', {}]] as const) {
      it(`${key}: allowedTools as ${label} is no wildcard, and MCP-004 still reports the next server`, async () => {
        const records = await scanConfig({
          [key]: {
            odd: { command: 'a-server', allowedTools },
            db: { command: 'db-server', args: ['--auth-mode', 'password', '--user', 'admin'] },
          },
        });
        expect(record(records, 'MCP-005')).toBeUndefined();
        expect(failed(records, 'MCP-004')).toBe(true);
        // `odd` lists no tool names, so TOOL-001 still names it.
        expect(record(records, 'TOOL-001')?.message).toContain('"odd"');
      });
    }

    for (const [label, url] of [['a number', 7], ['an object', {}]] as const) {
      it(`${key}: url as ${label} is no remote, and NET-001, MCP-008 and MCP-009 still read the next server`, async () => {
        const records = await scanConfig({
          [key]: {
            odd: { url },
            shell: { command: 'node', args: ['./server.js', '--host', '0.0.0.0'] },
          },
        });
        expect(record(records, 'NET-002')).toBeUndefined();
        expect(failed(records, 'NET-001')).toBe(true);
        expect(failed(records, 'MCP-008')).toBe(true);
        expect(failed(records, 'MCP-009')).toBe(true);
      });
    }
  }

  it('a malformed entry alone leaves MCP-008 passed and NET-002 and MCP-005 absent', async () => {
    const records = await scanConfig({ mcpServers: { odd: { allowedTools: 5, url: 7, args: 'x' }, empty: null } });
    expect(record(records, 'MCP-005')).toBeUndefined();
    expect(record(records, 'NET-002')).toBeUndefined();
    expect(record(records, 'MCP-008')?.passed).toBe(true);
    // `empty` is not a server, so TOOL-001 names `odd` alone.
    expect(record(records, 'TOOL-001')?.message).toContain('"odd"');
    expect(record(records, 'TOOL-001')?.message).not.toContain('"empty"');
  });

  it('the values of the right type are tested as before', async () => {
    const records = await scanConfig({
      mcpServers: {
        listed: { command: 'a-server', allowedTools: '*' },
        remote: { url: 'http://mcp.example.test/rpc' },
      },
    });
    expect(failed(records, 'MCP-005')).toBe(true);
    expect(failed(records, 'NET-002')).toBe(true);
  });
});

describe('TOOL-001 quotes server names escaped for the terminal and capped (#669)', { timeout: 120_000 }, () => {
  it('a control character in a name is shown, not sent', async () => {
    const esc = String.fromCharCode(0x1b);
    const records = await scanConfig({ mcpServers: { [`a${esc}[2Jb`]: { command: 'a-server' } } });
    const message = record(records, 'TOOL-001')?.message ?? '';
    expect(message).not.toContain(esc);
    expect(message).toContain('"a\\e[2Jb"');
  });

  it('a name longer than 60 characters is cut to 57 and marked', async () => {
    const long = 'w'.repeat(200);
    const records = await scanConfig({ mcpServers: { [long]: { command: 'a-server' } } });
    const message = record(records, 'TOOL-001')?.message ?? '';
    expect(message).toContain(`"${'w'.repeat(57)}..."`);
    expect(message).not.toContain('w'.repeat(58));
  });

  it('an ordinary name is quoted as it is written', async () => {
    const records = await scanConfig({ mcpServers: { 'files-1': { command: 'a-server' } } });
    expect(record(records, 'TOOL-001')?.message).toContain('"files-1"');
  });
});
