/**
 * #669 — the deterministic MCP, NET and TOOL checks read servers under every
 * key a client writes (`mcpServers` and `servers`), through one accessor.
 *
 * Before: MCP-003..005, MCP-008..010, NET-001/002 and TOOL-001..003 walked
 * `config.servers` only. On the issue's fixture keyed `mcpServers` (Claude
 * Code's spelling), MCP-005 emitted nothing and MCP-009 and TOOL-003 recorded
 * a pass for a server named `shell` running `sh`.
 *
 * Reading the second key exposed two defects that would have moved scores the
 * wrong way, so they are corrected in the same change:
 *   - TOOL-001 passed when ANY server had a non-empty `allowedTools`, `["*"]`
 *     included, so the accessor alone raised OASB-1 compliance on a wildcard
 *     grant. It now passes only when every server lists tool names and none
 *     contains `*`.
 *   - TOOL-003 and MCP-009 matched sensitive words as substrings, so every
 *     `filesystem` server read as `system`. They now match whole words of the
 *     server name.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { MCP_SERVER_MAP_KEYS, mcpServerEntries } from '../../src/mcp-clients';
import { tempDir } from '../helpers/temp-dir';

interface Record_ {
  checkId: string;
  passed?: boolean;
  severity?: string;
  message?: string;
  file?: string;
}

const ROOT_MCP_CHECK = /^(MCP-00[1-9]|MCP-010|TOOL-00[1-3]|NET-00[12])$/;
const MCP_PACKAGE_JSON = JSON.stringify({ name: 't', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } });

async function scanConfig(config: unknown, opts: { mcpPackage?: boolean } = {}): Promise<Record_[]> {
  const dir = tempDir('hma669-');
  writeFileSync(path.join(dir, 'mcp.json'), JSON.stringify(config));
  if (opts.mcpPackage) writeFileSync(path.join(dir, 'package.json'), MCP_PACKAGE_JSON);
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
  return ((result as unknown as { allFindings: Record_[] }).allFindings).filter((f) => ROOT_MCP_CHECK.test(f.checkId));
}

function verdicts(records: Record_[]): string[] {
  return records.map((r) => `${r.checkId}:${r.passed ? 'pass' : 'fail'}`).sort();
}

function failed(records: Record_[], checkId: string): boolean {
  return records.some((r) => r.checkId === checkId && r.passed === false);
}

function passed(records: Record_[], checkId: string): boolean {
  return records.some((r) => r.checkId === checkId && r.passed === true);
}

describe('mcpServerEntries (#669)', () => {
  it('reads every server map key, mcpServers first', () => {
    expect([...MCP_SERVER_MAP_KEYS]).toEqual(['mcpServers', 'servers']);
    const entries = mcpServerEntries({ servers: { b: { command: 'x' } }, mcpServers: { a: { command: 'y' } } });
    expect(entries.map(([name]) => name)).toEqual(['a', 'b']);
  });

  it('a server named the same under both keys is two entries, each evaluated once', () => {
    const entries = mcpServerEntries({ servers: { a: { command: 'x' } }, mcpServers: { a: { command: 'y' } } });
    expect(entries.map(([, s]) => (s as { command: string }).command)).toEqual(['y', 'x']);
  });

  it('a config or map that is not an object contributes nothing', () => {
    expect(mcpServerEntries(null)).toEqual([]);
    expect(mcpServerEntries('servers')).toEqual([]);
    expect(mcpServerEntries([{ servers: { a: {} } }])).toEqual([]);
    expect(mcpServerEntries({ servers: 7, mcpServers: 'a' })).toEqual([]);
  });

  it('a map written as a list is still walked, under its indexes, as the servers-only reads walked it', () => {
    expect(mcpServerEntries({ servers: [{ command: 'x' }] })).toEqual([['0', { command: 'x' }]]);
  });

  it('returns the parsed entry objects, so an in-place fix reaches the config', () => {
    const config = { mcpServers: { a: { args: ['/'] } } };
    const [[, server]] = mcpServerEntries(config);
    expect(server).toBe(config.mcpServers.a);
  });
});

describe('source: the deterministic MCP, NET and TOOL checks read servers through the accessor (#669)', () => {
  const SOURCE_PATH = path.join(__dirname, '../../src/hardening/scanner.ts');
  const code = readFileSync(SOURCE_PATH, 'utf-8')
    .split('\n')
    .map((text, i) => ({ n: i + 1, text }))
    .filter(({ text }) => !/^\s*(\/\/|\*|\/\*)/.test(text));

  it('no line reads a server map by one key', () => {
    const offenders = code.filter(({ text }) =>
      /\b(mcpConfig|config)\??\.(servers|mcpServers)\b|\[\s*['"`](servers|mcpServers)['"`]\s*\]/.test(text),
    );
    expect(offenders.map((o) => `${SOURCE_PATH}:${o.n}: ${o.text.trim()}`)).toEqual([]);
  });

  it('no line spells a server map key as a literal: the key set lives in MCP_SERVER_MAP_KEYS', () => {
    const offenders = code.filter(({ text }) => /(['"`])(servers|mcpServers)\1/.test(text));
    expect(offenders.map((o) => `${SOURCE_PATH}:${o.n}: ${o.text.trim()}`)).toEqual([]);
  });
});

describe('a config keyed mcpServers is measured like the same config keyed servers (#669)', { timeout: 120_000 }, () => {
  const SHELL = { command: 'sh', allowedTools: ['*'] };

  it("the issue's fixture: MCP-005, MCP-009, TOOL-001 and TOOL-003 fail under mcpServers", async () => {
    const records = await scanConfig({ mcpServers: { shell: SHELL } });
    expect(failed(records, 'MCP-005')).toBe(true);
    expect(failed(records, 'MCP-009')).toBe(true);
    expect(failed(records, 'TOOL-003')).toBe(true);
    expect(failed(records, 'TOOL-001')).toBe(true);
    expect(passed(records, 'MCP-009')).toBe(false);
    expect(passed(records, 'TOOL-003')).toBe(false);
  });

  it('the same server keyed servers gives the same verdict for every root MCP check', async () => {
    const underMcpServers = await scanConfig({ mcpServers: { shell: SHELL } });
    const underServers = await scanConfig({ servers: { shell: SHELL } });
    expect(verdicts(underMcpServers)).toEqual(verdicts(underServers));
  });

  it('every server-walking check reaches a server under mcpServers', async () => {
    const records = await scanConfig({
      mcpServers: {
        rootfs: { command: 'fs-server', args: ['/'] },
        bound: { command: 'node', args: ['./server.js', '--bind', '0.0.0.0', '--verbose'], maxTokens: 1000 },
        remote: { url: 'http://mcp.example.test/rpc' },
        db: { command: 'db-server', args: ['--auth-mode', 'password', '--user', 'admin'] },
      },
    });
    expect(failed(records, 'MCP-001')).toBe(true);
    expect(failed(records, 'NET-001')).toBe(true);
    expect(failed(records, 'NET-002')).toBe(true);
    expect(failed(records, 'MCP-004')).toBe(true);
    expect(failed(records, 'MCP-008')).toBe(true);
    expect(passed(records, 'TOOL-002')).toBe(true);
    expect(records.find((r) => r.checkId === 'MCP-010')?.message).toBe(
      'MCP logging appears to be configured - ensure sensitive data is not logged',
    );
  });

  it('a servers map written as a list keeps the reach the servers-only reads had', async () => {
    const records = await scanConfig({ servers: [{ command: 'node', args: ['--host', '0.0.0.0'] }] });
    expect(failed(records, 'NET-001')).toBe(true);
  });

  it('a file carrying both keys has both maps evaluated', async () => {
    const records = await scanConfig({
      servers: { bound: { command: 'node', args: ['--host', '0.0.0.0'] } },
      mcpServers: { remote: { url: 'http://mcp.example.test/rpc' } },
    });
    expect(failed(records, 'NET-001')).toBe(true);
    expect(failed(records, 'NET-002')).toBe(true);
  });
});

describe('TOOL-001 passes only when every server lists tool names without "*" (#669)', { timeout: 120_000 }, () => {
  for (const key of ['mcpServers', 'servers']) {
    it(`${key}: a wildcard grant is not a whitelist`, async () => {
      const records = await scanConfig({ [key]: { fs: { command: 'fs-server', allowedTools: ['*'] } } });
      expect(failed(records, 'TOOL-001')).toBe(true);
      expect(records.find((r) => r.checkId === 'TOOL-001')?.message).toContain('"fs"');
    });

    it(`${key}: a name pattern containing "*" is not a whitelist`, async () => {
      const records = await scanConfig({ [key]: { fs: { command: 'fs-server', allowedTools: ['read_file', 'write_*'] } } });
      expect(failed(records, 'TOOL-001')).toBe(true);
    });

    it(`${key}: one listed server does not pass the file for an unlisted one, and the failure names the unlisted one`, async () => {
      const records = await scanConfig({
        [key]: {
          listed: { command: 'a-server', allowedTools: ['read_file'] },
          open: { command: 'b-server' },
        },
      });
      const tool001 = records.find((r) => r.checkId === 'TOOL-001');
      expect(tool001?.passed).toBe(false);
      expect(tool001?.message).toContain('"open"');
      expect(tool001?.message).not.toContain('"listed"');
    });

    it(`${key}: every server listing tool names passes`, async () => {
      const records = await scanConfig({
        [key]: {
          a: { command: 'a-server', allowedTools: ['read_file'] },
          b: { command: 'b-server', allowedTools: ['list_directory', 'read_file'] },
        },
      });
      expect(passed(records, 'TOOL-001')).toBe(true);
    });
  }

  it('a server map with no server still fails, as before', async () => {
    const records = await scanConfig({ mcpServers: {} });
    expect(failed(records, 'TOOL-001')).toBe(true);
    expect(records.find((r) => r.checkId === 'TOOL-001')?.message).toBe(
      'Configure allowedTools to restrict MCP server capabilities',
    );
  });
});

describe('an allowedTools or url that is not a list or a string does not end the scan (#669)', { timeout: 120_000 }, () => {
  // Before: `allowedTools: {}` threw "server.allowedTools?.includes is not a
  // function" in MCP-005, and `url: 7` threw "server.url.startsWith is not a
  // function" in NET-002 (MCP-008 threw on `.includes` the same way), so
  // `secure` exited 1 with no report.
  for (const key of ['mcpServers', 'servers']) {
    it(`${key}: such a value declares no tools and no URL`, async () => {
      const records = await scanConfig({
        [key]: {
          a: { command: 'npx', allowedTools: {}, url: 7 },
          b: { command: 'npx', allowedTools: 3, url: { href: 'http://x' } },
        },
      });
      expect(records.some((r) => r.checkId === 'MCP-005')).toBe(false);
      expect(records.some((r) => r.checkId === 'NET-002')).toBe(false);
      expect(passed(records, 'MCP-008')).toBe(true);
      expect(failed(records, 'TOOL-001')).toBe(true);
    });

    it(`${key}: a non-list or empty allowedTools is not a whitelist`, async () => {
      for (const allowedTools of ['read_file', [], {}]) {
        const records = await scanConfig({ [key]: { fs: { command: 'npx', allowedTools } } });
        expect(failed(records, 'TOOL-001'), `allowedTools ${JSON.stringify(allowedTools)}`).toBe(true);
      }
    });

    it(`${key}: a string allowedTools and a string url are still read`, async () => {
      expect(failed(await scanConfig({ [key]: { a: { command: 'npx', allowedTools: '*' } } }), 'MCP-005')).toBe(true);
      expect(failed(await scanConfig({ [key]: { a: { url: 'http://mcp.example.test/sse' } } }), 'NET-002')).toBe(true);
    });
  }
});

describe('TOOL-003 and MCP-009 match whole words of the server name (#669)', { timeout: 120_000 }, () => {
  // The corpus benign fixture's shape: one read-only filesystem server.
  const FILESYSTEM = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', './docs'] };

  for (const mcpPackage of [false, true]) {
    it(`a server named filesystem is not read as system (MCP package.json: ${mcpPackage})`, async () => {
      const records = await scanConfig({ mcpServers: { filesystem: FILESYSTEM } }, { mcpPackage });
      expect(passed(records, 'MCP-009')).toBe(true);
      expect(passed(records, 'TOOL-003')).toBe(true);
      const severe = records.filter((r) => r.passed === false && (r.severity === 'high' || r.severity === 'critical'));
      // TOOL-001 failed on this server before #669 (no allowedTools); nothing else does.
      expect(severe.map((r) => r.checkId)).toEqual(['TOOL-001']);
    });
  }

  it('the same holds under servers, where the substring test failed it', async () => {
    const records = await scanConfig({ servers: { filesystem: FILESYSTEM } });
    expect(passed(records, 'MCP-009')).toBe(true);
    expect(passed(records, 'TOOL-003')).toBe(true);
  });

  const CASES: Array<[string, boolean, boolean]> = [
    // [server name, MCP-009 fails, TOOL-003 fails]
    ['execute-shell', true, true],
    ['Shell', true, true],
    ['my_system_tool', true, true],
    ['code.eval', true, true],
    ['run_command', false, true],
    ['spawn-worker', true, false],
    ['ecosystem', false, false],
    ['shellfish', false, false],
    ['evaluator', false, false],
  ];
  for (const [name, mcp009Fails, tool003Fails] of CASES) {
    it(`${name}: MCP-009 ${mcp009Fails ? 'fails' : 'passes'}, TOOL-003 ${tool003Fails ? 'fails' : 'passes'}`, async () => {
      const records = await scanConfig({ mcpServers: { [name]: { command: 'node', args: ['./server.js'] } } });
      expect(failed(records, 'MCP-009')).toBe(mcp009Fails);
      expect(failed(records, 'TOOL-003')).toBe(tool003Fails);
    });
  }
});

// A server field of the wrong type used to end the whole scan with no report:
// `"url": 7` with "server.url.startsWith is not a function", `"command": 7`
// with "server.command?.includes is not a function" and `"allowedTools": 7`
// with "server.allowedTools?.includes is not a function". The field is now
// skipped and every other server is still evaluated.
describe('a server field of the wrong type does not end the scan', { timeout: 120_000 }, () => {
  const MALFORMED: Array<[string, Record<string, unknown>]> = [
    ['url: 7', { url: 7 }],
    ['url: an object', { url: { href: 'http://mcp.example.test/rpc' } }],
    ['command: 7', { command: 7 }],
    ['command: an object', { command: { path: 'sh' } }],
    ['allowedTools: 7', { allowedTools: 7 }],
    ['allowedTools: an object', { allowedTools: { '*': true } }],
  ];
  for (const key of ['mcpServers', 'servers']) {
    for (const [label, fields] of MALFORMED) {
      it(`${key}: ${label} is skipped, and a well-formed server beside it is still evaluated`, async () => {
        const records = await scanConfig({
          [key]: {
            odd: fields,
            remote: { url: 'http://mcp.example.test/rpc', allowedTools: ['*'] },
          },
        });
        expect(failed(records, 'NET-002')).toBe(true);
        expect(failed(records, 'MCP-005')).toBe(true);
        const tool001 = records.find((r) => r.checkId === 'TOOL-001');
        expect(tool001?.passed).toBe(false);
        expect(tool001?.message).toContain('"odd"');
      });
    }
  }

  it('every malformed field and entry at once under mcpServers', async () => {
    const records = await scanConfig({
      mcpServers: { a: { command: 7, url: 7, allowedTools: 7, env: 'x', args: '--x' }, b: null, c: 'str' },
    });
    expect(failed(records, 'NET-002')).toBe(false);
    expect(failed(records, 'MCP-005')).toBe(false);
    expect(failed(records, 'TOOL-001')).toBe(true);
  });

  it('a command written as a list is still read for shell, as before', async () => {
    const records = await scanConfig({ mcpServers: { runner: { command: ['shell'] } } });
    expect(failed(records, 'MCP-002')).toBe(true);
  });

  it('an allowedTools written as the string "*" is still a wildcard grant, as before', async () => {
    const records = await scanConfig({ mcpServers: { runner: { command: 'node', allowedTools: '*' } } });
    expect(failed(records, 'MCP-005')).toBe(true);
  });
});
