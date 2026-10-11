/**
 * #1003 — SKILL-020 and SKILL-024 findings say `fixable: false`.
 *
 * Before: both checks set `fixable: true`, so `secure --json` reported them as
 * auto-fixable and `secure --fix --dry-run` counted them among the issues it
 * would fix, while no fix step writes frontmatter fields or an iteration
 * limit and docs/SECURITY_CHECKS.md lists both as not auto-fixable. The
 * values belong to the skill's author.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

/** The fields of a finding this file reads. */
interface Finding {
  checkId: string;
  passed: boolean;
  file?: string;
  fixable?: boolean;
  wouldFix?: boolean;
  fix?: string;
}

const SKILLS: Record<string, string> = {
  'no-frontmatter': '# Notes helper\n\nSummarises the notes the user points it at.\n',
  'incomplete-frontmatter': '---\nname: notes-helper\n---\n# Notes helper\n\nSummarises notes.\n',
  'unbounded-chain': '---\nname: chain-helper\nversion: 1.0.0\ncapabilities:\n  - tool:chain\n---\n# Chain helper\n\nRuns one tool after another.\n',
};

let failed: Finding[] = [];

beforeAll(async () => {
  const dir = tempDir('hma-1003-skill-fixable-');
  for (const [name, content] of Object.entries(SKILLS)) {
    fs.mkdirSync(path.join(dir, 'skills', name), { recursive: true });
    fs.writeFileSync(path.join(dir, 'skills', name, 'SKILL.md'), content);
  }
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true, dryRun: true });
  failed = ([...result.findings, ...(result.allFindings ?? [])] as Finding[]).filter(
    (f) => !f.passed && (f.checkId === 'SKILL-020' || f.checkId === 'SKILL-024'),
  );
}, 120_000);

describe('#1003 SKILL-020 and SKILL-024 are not reported as auto-fixable', () => {
  it.each([
    ['SKILL-020', 'skills/no-frontmatter/SKILL.md'],
    ['SKILL-020', 'skills/incomplete-frontmatter/SKILL.md'],
    ['SKILL-024', 'skills/unbounded-chain/SKILL.md'],
  ])('%s on %s', (checkId, file) => {
    const findings = failed.filter((f) => f.checkId === checkId && f.file === file);
    // Non-vacuity: the fixture raises the finding.
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.fixable).toBe(false);
      expect(f.wouldFix).not.toBe(true);
      // The manual remedy is still there.
      expect(f.fix).toBeTruthy();
    }
  });
});
