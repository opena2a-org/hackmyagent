/**
 * #757 — `init-mcp` on the Claude Code path wrote the `mcpServers` block into
 * `.claude/settings.json`, a file Claude Code does not read for project MCP
 * servers; `claude mcp list` then printed "No MCP servers configured" and the
 * advertised tools were never reachable. Claude Code reads `<dir>/.mcp.json`
 * (the positive control in the issue: the identical object copied there lists
 * the server). These cells pin the file the command writes, on every route to
 * the Claude Code target, and that the success record names that file.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initMcp } from '../../src/init-mcp';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'hma-757-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function serverEntry(file: string): { command: string; args: string[] } | undefined {
  const parsed = JSON.parse(readFileSync(file, 'utf-8')) as {
    mcpServers?: Record<string, { command: string; args: string[] }>;
  };
  return parsed.mcpServers?.hackmyagent;
}

describe('#757: the Claude Code target is <dir>/.mcp.json', () => {
  it('--tool claude writes .mcp.json and nothing under .claude/', () => {
    const result = initMcp(dir, 'claude');

    expect(result.tool).toBe('Claude Code');
    expect(result.configPath).toBe('.mcp.json');
    expect(result.created).toBe(true);
    expect(existsSync(join(dir, '.mcp.json'))).toBe(true);
    expect(existsSync(join(dir, '.claude', 'settings.json'))).toBe(false);

    const entry = serverEntry(join(dir, '.mcp.json'));
    expect(entry?.command).toBeTruthy();
    expect(entry?.args).toContain('--root');
  });

  it('a tree with a .claude/ directory but no config still routes to .mcp.json', () => {
    mkdirSync(join(dir, '.claude'));

    const result = initMcp(dir);

    expect(result.tool).toBe('Claude Code');
    expect(result.configPath).toBe('.mcp.json');
    expect(existsSync(join(dir, '.mcp.json'))).toBe(true);
    expect(existsSync(join(dir, '.claude', 'settings.json'))).toBe(false);
  });

  it('an existing .mcp.json is detected as Claude Code and merged, other servers kept', () => {
    writeFileSync(
      join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { other: { command: 'x', args: [] } } }, null, 2) + '\n',
    );

    const result = initMcp(dir);

    expect(result.tool).toBe('Claude Code');
    expect(result.configPath).toBe('.mcp.json');
    expect(result.created).toBe(true);
    const parsed = JSON.parse(readFileSync(join(dir, '.mcp.json'), 'utf-8')) as {
      mcpServers: Record<string, unknown>;
    };
    expect(Object.keys(parsed.mcpServers).sort()).toEqual(['hackmyagent', 'other']);
  });

  it('the default target (nothing detected) is .mcp.json, not .claude/settings.json', () => {
    const result = initMcp(dir);

    expect(result.configPath).toBe('.mcp.json');
    expect(existsSync(join(dir, '.claude'))).toBe(false);
  });

  it('Cursor and VS Code targets are unchanged', () => {
    expect(initMcp(dir, 'cursor').configPath).toBe('.cursor/mcp.json');
    expect(initMcp(dir, 'vs code').configPath).toBe('.vscode/mcp.json');
  });
});
