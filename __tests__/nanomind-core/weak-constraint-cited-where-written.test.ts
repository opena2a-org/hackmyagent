/**
 * AST-GOV-002 (weak constraint enforceability) names wording to change:
 * "should", "recommended", "try to". It was reported on
 * test/fixtures/governed-mcp/mcp.json, which holds none of those words, with
 * no line: mcp.json borrows its sibling SOUL.md's constraints as project
 * constraints, and the enforceability check ran over them as if they were
 * mcp.json's own. The wording lives at SOUL.md:39, which is reported there.
 *
 * Pinned here, on the fixture as it is tracked: no AST-GOV-002 on mcp.json,
 * and every AST-GOV-002 left cites a file and a line whose text holds the
 * advisory wording.
 */
import { describe, it, expect } from 'vitest';
import { cpSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

const FIXTURE = join(__dirname, '../../test/fixtures/governed-mcp');
const ADVISORY = /\b(should|recommended|try to)\b/i;

describe('AST-GOV-002 is cited on the file and line that hold the wording', () => {
  it('governed-mcp: none on mcp.json; the one left is SOUL.md:39', async () => {
    const dir = join(tempDir('hma-gov002-cite-'), 'governed-mcp');
    cpSync(FIXTURE, dir, { recursive: true });

    const { astFindings } = await runNanoMindScan(dir, []);
    const gov002 = astFindings.filter(f => !f.passed && f.checkId === 'AST-GOV-002');

    expect(gov002.filter(f => f.file === 'mcp.json').map(f => f.message)).toEqual([]);
    expect(gov002.map(f => `${f.file}:${f.line}`)).toEqual(['SOUL.md:39']);
    for (const f of gov002) {
      expect(f.line, `${f.file}: ${f.message}`).toBeDefined();
      const cited = readFileSync(join(dir, f.file!), 'utf-8').split('\n')[f.line! - 1];
      expect(cited, `${f.file}:${f.line}`).toMatch(ADVISORY);
    }
  });
});
