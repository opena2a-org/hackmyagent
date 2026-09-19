/**
 * HMA-71 — `init-mcp` writes the key the CLIENT reads, and the spelling its own
 * help text advertises resolves.
 *
 * Releases through 0.33.2 wrote `mcpServers` into every client file, including
 * `.vscode/mcp.json`, whose top-level key is `servers` — the key this tree's own
 * reader of that file, VSCODE-002, has always walked. One tree, writer and
 * reader disagreeing on the key: `hackmyagent secure` could not see the VS Code
 * entry `hackmyagent init-mcp` had just written.
 *
 * Sitting on the same table row: `-t vscode`, the spelling `--tool`'s own help
 * lists, was refused by a matcher that asked whether `'vs code'` CONTAINS
 * `'vscode'`.
 *
 * AC7's cells are the regression pin on everything the command writes that does
 * NOT move: the Claude Code and Cursor targets, and `.claude/` staying untouched
 * on every route (#757).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { initMcp, buildMcpServerEntry } from '../../src/init-mcp';

const CLI_SOURCE = readFileSync(join(__dirname, '../../src/cli.ts'), 'utf-8');

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'hma-71-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

/** A fresh empty scratch directory: one target per cell, never shared. */
function scratch(): string {
  return mkdtempSync(join(root, 'd-'));
}

/** A scratch directory holding an empty `.vscode/` and no config file. */
function vscodeDir(): string {
  const dir = scratch();
  mkdirSync(join(dir, '.vscode'));
  return dir;
}

type ServerEntry = { command: string; args: string[]; cwd?: string };
type Parsed = Record<string, Record<string, ServerEntry> | undefined>;

function parse(file: string): Parsed {
  return JSON.parse(readFileSync(file, 'utf-8')) as Parsed;
}

/** Every top-level key of the document whose value carries a `hackmyagent` entry. */
function keysCarryingHackmyagent(config: Parsed): string[] {
  return Object.entries(config)
    .filter(([, v]) => Boolean(v) && typeof v === 'object' && 'hackmyagent' in (v as object))
    .map(([k]) => k)
    .sort();
}

describe('HMA-71.AC1: the VS Code target writes the key VS Code reads', () => {
  const ROUTES: Array<[string, string | undefined]> = [
    ['--tool "vs code"', 'vs code'],
    ['--tool vscode', 'vscode'],
    ['detection from an empty .vscode/ directory', undefined],
  ];

  it.each(ROUTES)(
    'HMA-71.AC1 %s writes servers.hackmyagent into .vscode/mcp.json and nothing under another key',
    (_label, tool) => {
      const dir = vscodeDir();

      const result = initMcp(dir, tool);

      expect(result.tool).toBe('VS Code');
      expect(result.configPath).toBe('.vscode/mcp.json');

      const config = parse(join(dir, '.vscode', 'mcp.json'));
      expect(config.servers?.hackmyagent).toEqual(buildMcpServerEntry([resolve(dir)]));
      expect(keysCarryingHackmyagent(config)).toEqual(['servers']);
    },
  );

  it('HMA-71.AC1 an existing servers map keeps its other entries and gains hackmyagent', () => {
    const dir = vscodeDir();
    const other = { command: 'x', args: [] as string[] };
    writeFileSync(join(dir, '.vscode', 'mcp.json'), JSON.stringify({ servers: { other } }, null, 2) + '\n');

    const result = initMcp(dir);

    expect(result).toMatchObject({ tool: 'VS Code', configPath: '.vscode/mcp.json', created: true, updated: false });
    const config = parse(join(dir, '.vscode', 'mcp.json'));
    expect(config.servers?.other).toEqual(other);
    expect(Object.keys(config.servers ?? {}).sort()).toEqual(['hackmyagent', 'other']);
  });

  it('HMA-71.AC1 a stale mcpServers.hackmyagent left by an earlier release is repaired in place', () => {
    // The bytes every release through 0.33.2 wrote into the VS Code file: the
    // pre-#463 entry, under a key VS Code does not read.
    const dir = vscodeDir();
    writeFileSync(
      join(dir, '.vscode', 'mcp.json'),
      JSON.stringify(
        { mcpServers: { hackmyagent: { command: 'npx', args: ['-y', 'hackmyagent', 'mcp-serve'] } } },
        null,
        2,
      ) + '\n',
    );

    const result = initMcp(dir);

    expect(result).toMatchObject({ tool: 'VS Code', configPath: '.vscode/mcp.json', updated: true });
    const config = parse(join(dir, '.vscode', 'mcp.json'));
    expect(config.servers?.hackmyagent?.args).toContain('--root');
    expect(keysCarryingHackmyagent(config)).toEqual(['servers']);
  });

  it('HMA-71.AC1 a second run on the file the first run wrote changes nothing', () => {
    const dir = vscodeDir();
    initMcp(dir, 'vscode');
    const before = readFileSync(join(dir, '.vscode', 'mcp.json'), 'utf-8');

    const again = initMcp(dir, 'vscode');

    expect(again).toMatchObject({ created: false, updated: false });
    expect(readFileSync(join(dir, '.vscode', 'mcp.json'), 'utf-8')).toBe(before);
  });
});

describe('HMA-71.AC2: the tool spelling the help text lists resolves', () => {
  const SPELLINGS: Array<[string, string, string]> = [
    ['vscode', 'VS Code', '.vscode/mcp.json'],
    ['vs code', 'VS Code', '.vscode/mcp.json'],
    ['VSCode', 'VS Code', '.vscode/mcp.json'],
    ['claude', 'Claude Code', '.mcp.json'],
    ['cursor', 'Cursor', '.cursor/mcp.json'],
  ];

  it.each(SPELLINGS)('HMA-71.AC2 --tool %s selects %s', (spelling, tool, configPath) => {
    const result = initMcp(scratch(), spelling);

    expect(result.tool).toBe(tool);
    expect(result.configPath).toBe(configPath);
  });

  it('HMA-71.AC2 an unrecognised tool throws Unknown tool and writes no file', () => {
    const dir = scratch();

    expect(() => initMcp(dir, 'emacs')).toThrow(/^Unknown tool: emacs/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('HMA-71.AC2 every spelling the -t, --tool description lists resolves to its own target', () => {
    const option = /'-t, --tool <name>',\s*'Force specific tool: ([^']+)'/.exec(CLI_SOURCE);
    expect(option, 'the -t, --tool option description was not found in src/cli.ts').not.toBeNull();

    const spellings = option![1].split(',').map((s) => s.trim());
    expect(spellings.length).toBeGreaterThan(0);

    const resolved = spellings.map((s) => initMcp(scratch(), s).tool);
    // Exactly the spellings the matcher accepts: one per client target, and
    // every target named. A spelling the matcher refuses throws above.
    expect([...resolved].sort()).toEqual(['Claude Code', 'Cursor', 'VS Code']);
  });
});

describe('HMA-71.AC7: nothing else the command writes moves', () => {
  it('HMA-71.AC7 --tool cursor writes .cursor/mcp.json under mcpServers and no servers key', () => {
    const dir = scratch();

    expect(initMcp(dir, 'cursor').configPath).toBe('.cursor/mcp.json');

    const config = parse(join(dir, '.cursor', 'mcp.json'));
    expect(config.mcpServers?.hackmyagent?.args).toContain('--root');
    expect(config.servers).toBeUndefined();
  });

  it('HMA-71.AC7 --tool claude writes .mcp.json under mcpServers and no servers key', () => {
    const dir = scratch();

    expect(initMcp(dir, 'claude').configPath).toBe('.mcp.json');

    const config = parse(join(dir, '.mcp.json'));
    expect(config.mcpServers?.hackmyagent?.args).toContain('--root');
    expect(config.servers).toBeUndefined();
  });

  it('HMA-71.AC7 no route through initMcp writes anything under .claude/ (#757)', () => {
    for (const tool of ['claude', 'cursor', 'vscode', 'vs code', undefined]) {
      const dir = scratch();

      initMcp(dir, tool);

      expect(existsSync(join(dir, '.claude')), `--tool ${tool} created .claude/`).toBe(false);
    }

    // The detection route that a `.claude/` directory already selects: the
    // directory is the DETECTION signal, never a write target.
    const detected = scratch();
    mkdirSync(join(detected, '.claude'));

    expect(initMcp(detected).configPath).toBe('.mcp.json');
    expect(readdirSync(join(detected, '.claude'))).toEqual([]);
  });
});
