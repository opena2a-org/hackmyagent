/**
 * HMA-71 — MCP-001 reads the key Claude Code's own file carries.
 *
 * #637 put `.mcp.json` into the root discovery set, so the file is READ. The
 * walk inside it was still `config.servers` alone, and `mcpServers` — the key
 * Claude Code's project-scope file actually carries, and the key `init-mcp`
 * writes there — occurred zero times in scanner.ts. A `.mcp.json` scoping a
 * filesystem server at `/` was therefore silent: the file was opened, the
 * servers were live, and every MCP-scoped control read clean.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { buildMcpServerEntry } from '../../src/init-mcp';
import type { SecurityFinding } from '../../src/hardening/security-check';

/** The bytes of a Claude Code project config whose filesystem server is scoped at `/`. */
const ROOT_SCOPED = JSON.stringify(
  { mcpServers: { filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] } } },
  null,
  2,
) + '\n';

let dir: string;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-71-mcp001-'));
  // `mcp`-typed: the MCP- check group applies to MCP projects only.
  await fs.writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'test-project', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }, null, 2),
  );
});

afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

function mcp001(findings: SecurityFinding[]): SecurityFinding | undefined {
  return findings.find((f) => f.checkId === 'MCP-001' && f.passed === false);
}

describe('HMA-71.AC4: MCP-001 reads mcpServers in the root config spellings', () => {
  it.each([['.mcp.json'], ['mcp.json']])(
    'HMA-71.AC4 a root-scoped mcpServers entry in %s is reported against that file',
    async (name) => {
      await fs.writeFile(path.join(dir, name), ROOT_SCOPED);

      const result = await new HardeningScanner().scan({ targetDir: dir });

      const finding = mcp001(result.findings);
      expect(finding, `MCP-001 was silent on a root-scoped mcpServers entry in ${name}`).toBeDefined();
      expect(finding?.passed).toBe(false);
      expect(finding?.file).toBe(name);
    },
  );

  it('HMA-71.AC4 --fix rewrites the / argument of an mcpServers entry in .mcp.json', async () => {
    await fs.writeFile(path.join(dir, '.mcp.json'), ROOT_SCOPED);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    const finding = result.findings.find((f) => f.checkId === 'MCP-001');
    expect(finding?.fixed).toBe(true);
    const after = JSON.parse(await fs.readFile(path.join(dir, '.mcp.json'), 'utf-8')) as {
      mcpServers: Record<string, { args: string[] }>;
    };
    expect(after.mcpServers.filesystem.args).toContain('./data');
    expect(after.mcpServers.filesystem.args).not.toContain('/');
  });

  it('HMA-71.AC4 the root-scoped entry init-mcp writes is not reported', async () => {
    // The control: `init-mcp`'s own entry names the project with `--root` and
    // no bare `/` or `~`. Reading the key must not make the command that
    // writes it fail its own check.
    const inside = path.join(dir, 'workspace');
    await fs.mkdir(inside);
    await fs.writeFile(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { hackmyagent: buildMcpServerEntry([inside]) } }, null, 2) + '\n',
    );

    const result = await new HardeningScanner().scan({ targetDir: dir });

    expect(mcp001(result.findings)).toBeUndefined();
    expect(mcp001(result.allFindings)).toBeUndefined();
  });
});
