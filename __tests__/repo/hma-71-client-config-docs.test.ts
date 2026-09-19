/**
 * HMA-71 — the two documents a user reads say what the command does.
 *
 * README's "Verify what the server is allowed to reach" line told the reader to
 * grep `.claude/settings.json`, a file `init-mcp` has not written since #757.
 * Someone following it greps an absent or inert file and concludes the server
 * was never configured.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const README = readFileSync(join(__dirname, '../../README.md'), 'utf-8');
const CHANGELOG = readFileSync(join(__dirname, '../../CHANGELOG.md'), 'utf-8');

/** The body of a `## ` section, up to the next `## ` heading. */
function section(source: string, heading: string): string {
  const start = source.indexOf(heading);
  expect(start, `${heading} was not found`).toBeGreaterThan(-1);
  const rest = source.slice(start + heading.length);
  const end = rest.search(/\n## /);
  return end === -1 ? rest : rest.slice(0, end);
}

describe('HMA-71.AC6: README and CHANGELOG name the files init-mcp writes', () => {
  const mcpSection = section(README, '\n## MCP server\n');

  it('HMA-71.AC6 the verify line names the file each client reads', () => {
    const verify = mcpSection.split('\n').filter((l) => l.startsWith('grep -A3 hackmyagent'));
    expect(verify).toHaveLength(1);

    for (const clientFile of ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
      expect(verify[0]).toContain(clientFile);
    }
  });

  it('HMA-71.AC6 no line describing init-mcp output names .claude/settings.json', () => {
    const offenders = mcpSection
      .split('\n')
      .map((text, i) => ({ text, i }))
      .filter(({ text }) => text.includes('.claude/settings.json'));

    expect(offenders.map((o) => o.text.trim())).toEqual([]);
  });

  const unreleased = section(CHANGELOG, '\n## [Unreleased]\n');

  it('HMA-71.AC6 the Unreleased section carries an entry for the key each client reads', () => {
    const entry = unreleased.split(/\n### /).find((e) => e.includes('--tool vscode'));
    expect(entry, 'no [Unreleased] entry names the `--tool vscode` spelling').toBeDefined();

    for (const token of ['init-mcp', '.vscode/mcp.json', '`servers`', '--tool vscode', 'MCP-001', 'mcpServers', '.mcp.json']) {
      expect(entry).toContain(token);
    }
  });

  it('HMA-71.AC6 the Unreleased section no longer calls the VS Code target unchanged', () => {
    expect(unreleased).not.toMatch(/and VS Code \(`\.vscode\/mcp\.json`\) are\s+unchanged/);
  });
});
