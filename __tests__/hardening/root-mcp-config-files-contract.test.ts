/**
 * #637 — the root MCP config discovery set is ONE constant.
 *
 * The deterministic MCP checks read `mcp.json` at the target root. `.mcp.json`
 * — the project-scope file Claude Code reads — was not in their discovery set,
 * so a tree whose servers lived there scored HIGHER than the same servers in
 * `mcp.json`: OASB-1 controls 2.3, 4.1 and 5.2 read not-applicable while the
 * servers were live (33% as `mcp.json`, 36% as `.mcp.json` on the issue's
 * fixture at efc862a).
 *
 * The fix is a single exported constant, `ROOT_MCP_CONFIG_FILES`, consumed by
 * every root read site and every list that names the root config. This test
 * pins the contract in both directions against the SOURCE, the way
 * static-check-source-extensions.test.ts pins JS_FAMILY_EXTENSIONS: a future
 * site that spells the file by hand re-opens the split, and a future
 * spelling added to the constant reaches every consumer without a census.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT_MCP_CONFIG_FILES, ROOT_MCP_CONFIG_SUBJECT, HardeningScanner } from '../../src/hardening/scanner';

const SOURCE_PATH = join(__dirname, '../../src/hardening/scanner.ts');
const SOURCE = readFileSync(SOURCE_PATH, 'utf-8');
const LINES = SOURCE.split('\n');

/** Lines that name the root config as a whole string literal: 'mcp.json' / "mcp.json" / `mcp.json`. */
function wholeLiteralLines(): Array<{ n: number; text: string }> {
  return LINES.map((text, i) => ({ n: i + 1, text })).filter(({ text }) => /(['"`])mcp\.json\1/.test(text));
}

describe('ROOT_MCP_CONFIG_FILES contract (#637)', () => {
  it('names both root spellings, the historical subject first', () => {
    expect([...ROOT_MCP_CONFIG_FILES]).toEqual(['mcp.json', '.mcp.json']);
  });

  it('the not-applicable subject names the set and carries no comma (cli.ts joins subjects with ", ")', () => {
    expect(ROOT_MCP_CONFIG_SUBJECT).toBe('mcp.json or .mcp.json');
    expect(ROOT_MCP_CONFIG_SUBJECT).not.toContain(',');
  });

  it('direction 1: no root read site, record, or list names mcp.json by a bare literal', () => {
    const offenders = wholeLiteralLines()
      // The constant's own definition.
      .filter(({ text }) => !/ROOT_MCP_CONFIG_FILES = \[/.test(text))
      // Other subjects that happen to share the basename: their own checks
      // (.cursor/, .vscode/) or agent discovery (.well-known/).
      .filter(({ text }) => !/\.cursor|\.vscode|\.well-known/.test(text))
      // Comments.
      .filter(({ text }) => !/^\s*(\/\/|\*|\/\*)/.test(text));
    expect(offenders.map((o) => `${SOURCE_PATH}:${o.n}: ${o.text.trim()}`)).toEqual([]);
  });

  it('direction 2: the six root read sites and the five lists consume the constant', () => {
    // The five check functions that read the root config.
    expect((SOURCE.match(/await readRootMcpConfigs\(targetDir\)/g) ?? []).length).toBe(5);
    // The platform-label probe.
    expect(SOURCE).toMatch(/for \(const name of ROOT_MCP_CONFIG_FILES\) \{\s*\n\s*try \{\s*\n\s*await fs\.access\(path\.join\(targetDir, name\)\)/);
    // CONFIG_CANDIDATE_NAMES, BACKUP_FILES, rootProbeOrder, PERM-002, WEBEXPOSE-003.
    expect((SOURCE.match(/\.\.\.ROOT_MCP_CONFIG_FILES/g) ?? []).length).toBe(5);
  });

  it('the auto-fix backup manifest pre-seeds every spelling a fix can write', () => {
    // MCP-001 and MCP-003 write back through applyFixWrite to whichever file
    // they read; a file the fixer modifies that createBackup never pre-seeded
    // is the #262/#271 class.
    const backupFiles = (HardeningScanner as unknown as { BACKUP_FILES: readonly string[] }).BACKUP_FILES;
    for (const name of ROOT_MCP_CONFIG_FILES) {
      expect(backupFiles).toContain(name);
    }
  });

  it('every not-applicable record for the root config names the set, not one spelling', () => {
    // The emitter literals: notApplicableRecord(..., SUBJECT, ...) and the
    // TOOL-001 hand-built record. A record naming 'mcp.json' alone would tell
    // the reader the wrong file to create.
    const naSubjects = SOURCE.match(/notApplicableRecord\(\{ checkId: '(MCP-00[6-9]|TOOL-00[23])'[^\n]*\}, ([^,]+),/g) ?? [];
    expect(naSubjects.length).toBe(6);
    for (const call of naSubjects) {
      expect(call).toContain('ROOT_MCP_CONFIG_SUBJECT,');
    }
    expect(SOURCE).toMatch(/subject: ROOT_MCP_CONFIG_SUBJECT,/);
    expect(SOURCE).not.toMatch(/outside its scope/);
  });
});
