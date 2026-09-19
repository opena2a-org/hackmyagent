/**
 * HMA-71 — the client targets are ONE definition.
 *
 * Which file a client loads, and which top-level key it loads its server map
 * from, is an external fact. This tree records it once and routes it: the
 * writer (`init-mcp`) and the readers (`checkVscodeConfig`, and the root MCP
 * checks through `ROOT_MCP_CONFIG_FILES`) consume the same records rather than
 * each spelling the paths by hand.
 *
 * That is not decoration. At 0.33.2 the table carried a `mcpKey` field declared
 * and read by NO code — four occurrences, all inside the table — while the
 * writer hard-coded `config.mcpServers` for every target. The field said
 * `servers` was wanted for VS Code and the writer wrote `mcpServers` anyway,
 * with nothing to fail.
 *
 * Pinned in both directions against the SOURCE, in the pattern of
 * __tests__/hardening/root-mcp-config-files-contract.test.ts (#637): a future
 * site that spells a client path by hand re-opens the split, and a value
 * changed in the constant reaches every consumer without a census.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MCP_CLIENT_TARGETS, MCP_SERVER_MAP_KEYS, VSCODE_CLIENT } from '../src/mcp-clients';
import { ROOT_MCP_CONFIG_FILES } from '../src/hardening/scanner';

const INIT_MCP_PATH = join(__dirname, '../src/init-mcp.ts');
const SCANNER_PATH = join(__dirname, '../src/hardening/scanner.ts');
const INIT_MCP_SOURCE = readFileSync(INIT_MCP_PATH, 'utf-8');
const SCANNER_SOURCE = readFileSync(SCANNER_PATH, 'utf-8');

/** A client config path written as a whole string literal: '.mcp.json', ".vscode/mcp.json", ... */
const CLIENT_PATH_LITERAL = /(['"`])(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json)\1/;

/** Comment lines carry the reasoning; they are allowed to name the paths. */
const COMMENT = /^\s*(\/\/|\*|\/\*)/;

/**
 * The lines of a method, from its signature to the `  }` that closes it at
 * class-member indentation. Every close inside the body is indented deeper.
 */
function methodBody(source: string, signature: string): Array<{ n: number; text: string }> {
  const lines = source.split('\n');
  const start = lines.findIndex((l) => l.includes(signature));
  expect(start, `${signature} was not found`).toBeGreaterThan(-1);
  const end = lines.findIndex((l, i) => i > start && /^ {2}\}\s*$/.test(l));
  expect(end, `the close of ${signature} was not found`).toBeGreaterThan(start);
  return lines.slice(start, end + 1).map((text, i) => ({ n: start + i + 1, text }));
}

function offenders(lines: Array<{ n: number; text: string }>, file: string): string[] {
  return lines
    .filter(({ text }) => !COMMENT.test(text))
    .filter(({ text }) => CLIENT_PATH_LITERAL.test(text))
    .map(({ n, text }) => `${file}:${n}: ${text.trim()}`);
}

describe('HMA-71.AC3: every client target is one exported constant', () => {
  const EXPECTED = [
    { name: 'Claude Code', configPath: '.mcp.json', mcpKey: 'mcpServers' },
    { name: 'Cursor', configPath: '.cursor/mcp.json', mcpKey: 'mcpServers' },
    { name: 'VS Code', configPath: '.vscode/mcp.json', mcpKey: 'servers' },
  ];

  it('HMA-71.AC3 direction 2: one record per client, each naming the key that client reads', () => {
    expect(MCP_CLIENT_TARGETS).toHaveLength(EXPECTED.length);
    for (const expected of EXPECTED) {
      const record = MCP_CLIENT_TARGETS.find((t) => t.name === expected.name);
      expect(record, `no record named ${expected.name}`).toBeDefined();
      expect(record).toMatchObject(expected);
    }
  });

  it('HMA-71.AC3 the Claude Code target is one of the root MCP config spellings the checks read', () => {
    const claude = MCP_CLIENT_TARGETS.find((t) => t.name === 'Claude Code')!;

    expect([...ROOT_MCP_CONFIG_FILES]).toContain(claude.configPath);
  });

  it('HMA-71.AC3 the server-map keys are derived from the records, not listed a second time', () => {
    expect([...MCP_SERVER_MAP_KEYS].sort()).toEqual(['mcpServers', 'servers']);
    for (const target of MCP_CLIENT_TARGETS) {
      expect(MCP_SERVER_MAP_KEYS).toContain(target.mcpKey);
    }
  });

  it('HMA-71.AC3 direction 1: src/init-mcp.ts names no client config path by a bare literal', () => {
    const lines = INIT_MCP_SOURCE.split('\n').map((text, i) => ({ n: i + 1, text }));

    expect(offenders(lines, INIT_MCP_PATH)).toEqual([]);
    // No second table: the `mcpKey`/`configPath` records live in one module.
    expect(INIT_MCP_SOURCE).not.toMatch(/mcpKey:\s*['"`]/);
    expect(INIT_MCP_SOURCE).toMatch(/import \{[^}]*MCP_CLIENT_TARGETS[^}]*\} from '\.\/mcp-clients'/);
  });

  it('HMA-71.AC3 direction 1: checkVscodeConfig names no client config path by a bare literal', () => {
    const body = methodBody(SCANNER_SOURCE, 'private async checkVscodeConfig(');

    expect(offenders(body, SCANNER_PATH)).toEqual([]);
    // Non-vacuity: the path it reads and the subject of its two
    // not-applicable records come off the VS Code record.
    const uses = body.filter(({ text }) => text.includes('VSCODE_CLIENT.configPath'));
    expect(uses.length).toBeGreaterThanOrEqual(3);
  });

  it('HMA-71.AC3 the VS Code record is the one checkVscodeConfig reports as its subject', () => {
    expect(VSCODE_CLIENT.name).toBe('VS Code');
    expect(VSCODE_CLIENT.configPath).toBe('.vscode/mcp.json');
    expect(VSCODE_CLIENT.mcpKey).toBe('servers');
  });
});
