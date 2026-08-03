/**
 * File discovery for the Layer 2 structural analyzers.
 *
 * A file type that is not discovered is invisible to EVERY structural analyzer
 * at once, silently and with no error — the failure looks like a clean scan.
 * `.mcp.json` was missing, so a live token in Claude Code's project-scope MCP
 * file scored 96/100 while the byte-identical `.cursor/mcp.json` scored 69/100.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { StructuralAnalyzer } from '../../src/semantic/structural';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('structural file discovery', () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-discovery-'));
    fs.mkdirSync(path.join(dir, '.cursor'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.vscode'), { recursive: true });
    const cfg = JSON.stringify({ mcpServers: { gh: { command: 'npx', env: { GITHUB_TOKEN: 'x' } } } }, null, 2);
    for (const rel of ['mcp.json', '.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
      fs.writeFileSync(path.join(dir, rel), cfg);
    }
  });

  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('discovers every MCP config location, including the project-scope .mcp.json', async () => {
    const files = await new StructuralAnalyzer().discoverFiles(dir);
    const found = files.filter(f => f.type === 'mcp_config').map(f => path.basename(f.path));
    // `.mcp.json` is the file Claude Code writes for PROJECT scope — the one
    // that gets committed and shared. Missing it meant SEM-CRED-004 never ran
    // on the most-shared MCP config in the ecosystem.
    for (const rel of ['mcp.json', '.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
      expect(
        files.some(f => f.path.endsWith(rel) && f.type === 'mcp_config'),
        `${rel} must be discovered as mcp_config. Found: ${found.join(', ')}`,
      ).toBe(true);
    }
  });

  it('classifies a discovered .mcp.json as mcp_config, not as a generic config file', async () => {
    // Discovery alone is not enough — the TYPE is what routes it to the MCP
    // analyzers. A `.mcp.json` typed `config_file` would still miss SEM-CRED-004.
    const files = await new StructuralAnalyzer().discoverFiles(dir);
    const dotMcp = files.find(f => path.basename(f.path) === '.mcp.json');
    expect(dotMcp, '.mcp.json must be discovered at all').toBeDefined();
    expect(dotMcp?.type).toBe('mcp_config');
  });
});
