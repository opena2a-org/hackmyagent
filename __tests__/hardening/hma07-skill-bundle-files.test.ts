/**
 * HMA-07.AC2 — bundled non-Markdown skill files are analyzed.
 *
 * A skill is a DIRECTORY. `SKILL.md` is what the agent is told; `scripts/`,
 * `hooks/` and `tests/` beside it are what runs. On origin/main 957bb65
 * `findSkillFiles` admitted only `SKILL.md` and `*.skill.md`
 * (`src/hardening/scanner.ts:11189-11191`) and the generic `walkDirectory`
 * selected by extension alone, so moving the payload one file across — out of
 * the Markdown and into `scripts/setup.sh` — was enough to be unread.
 *
 * Three files, three different reasons the pre-fix walk missed them:
 *   scripts/setup.sh   depth 2 below the skill, not a skill file
 *   scripts/install    EXTENSIONLESS — nothing an extension list can match
 *   tests/x.py         a language the skill checks never opened
 *
 * The assertion is on the EVIDENCE naming all three, not on a finding count.
 * One finding per skill directory citing every payload file is the reviewable
 * unit: three separate findings would let a reader fix `scripts/setup.sh`, see
 * the count drop, and ship the other two.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import {
  BUNDLE_SKILL_MD,
  BUNDLE_SETUP_SH,
  BUNDLE_INSTALL,
  BUNDLE_TEST_PY,
} from '../helpers/hma07-skill-fixtures';

type Finding = {
  checkId: string;
  passed: boolean;
  file?: string;
  message?: string;
  evidence?: { kind: string; lines?: Array<{ n: number; content: string; why: string }> };
};

async function writeFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

async function bundleFindings(targetDir: string): Promise<Finding[]> {
  const result = await new HardeningScanner().scan({ targetDir, autoFix: false });
  const findings = (result.allFindings || result.findings || []) as Finding[];
  return findings.filter(f => !f.passed && f.checkId === 'SKILL-006' && f.evidence?.kind === 'positive');
}

/** Lay down `<root>/<skillsDir>/doc-tools/` with SKILL.md and the three payload files. */
async function writeBundledSkill(root: string, skillsDir: string): Promise<void> {
  const skill = path.join(root, ...skillsDir.split('/'), 'doc-tools');
  await writeFile(path.join(skill, 'SKILL.md'), BUNDLE_SKILL_MD);
  await writeFile(path.join(skill, 'scripts', 'setup.sh'), BUNDLE_SETUP_SH);
  await writeFile(path.join(skill, 'scripts', 'install'), BUNDLE_INSTALL);
  await writeFile(path.join(skill, 'tests', 'x.py'), BUNDLE_TEST_PY);
}

describe('HMA-07.AC2 bundled non-Markdown skill files', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma07-skill-bundle-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  for (const skillsDir of ['skills', '.claude/skills']) {
    it(`HMA-07.AC2 a finding's evidence names scripts/setup.sh, scripts/install and tests/x.py for a skill under ${skillsDir}/`, async () => {
      const root = path.join(tempDir, skillsDir === 'skills' ? 'plain' : 'claude');
      await writeBundledSkill(root, skillsDir);

      const findings = await bundleFindings(root);
      expect(findings.length).toBe(1);

      const cited = (findings[0].evidence?.lines || []).map(l => l.why).join('\n');
      for (const bundled of ['scripts/setup.sh', 'scripts/install', 'tests/x.py']) {
        expect(cited).toContain(path.join(skillsDir, 'doc-tools', bundled).split(path.sep).join('/'));
      }

      // Every citation carries the offending line and a 1-based line number, so
      // the evidence is reviewable rather than a list of filenames.
      for (const line of findings[0].evidence?.lines || []) {
        expect(line.n).toBeGreaterThan(0);
        expect(line.content.length).toBeGreaterThan(0);
      }
    });
  }

  it('HMA-07.AC2 the extensionless scripts/install is admitted by its shebang, not by an extension', async () => {
    const root = path.join(tempDir, 'shebang-only');
    const skill = path.join(root, 'skills', 'doc-tools');
    await writeFile(path.join(skill, 'SKILL.md'), BUNDLE_SKILL_MD);
    await writeFile(path.join(skill, 'scripts', 'install'), BUNDLE_INSTALL);
    // Same payload, same directory, no shebang and no extension: not a script.
    await writeFile(path.join(skill, 'scripts', 'NOTES'), BUNDLE_INSTALL.replace('#!/bin/sh\n', ''));

    const findings = await bundleFindings(root);
    expect(findings.length).toBe(1);
    const cited = (findings[0].evidence?.lines || []).map(l => l.why).join('\n');
    expect(cited).toContain('scripts/install');
    expect(cited).not.toContain('scripts/NOTES');
  });

  it('HMA-07.AC2 an ordinary bundled script raises nothing (the conjunction is what fires, not the presence of a script)', async () => {
    const root = path.join(tempDir, 'benign-bundle');
    const skill = path.join(root, 'skills', 'doc-tools');
    await writeFile(path.join(skill, 'SKILL.md'), BUNDLE_SKILL_MD);
    await writeFile(path.join(skill, 'scripts', 'setup.sh'), '#!/usr/bin/env bash\nnpm ci\nnpm run build\n');
    await writeFile(path.join(skill, 'scripts', 'publish'), '#!/bin/sh\ncurl -sf -X POST -d @dist/manifest.json https://registry.example.com/publish\n');
    await writeFile(path.join(skill, 'tests', 'x.py'), 'import os\n\ndef test_home():\n    assert os.path.expanduser("~/.ssh")\n');

    expect(await bundleFindings(root)).toEqual([]);
  });
});
