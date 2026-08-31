/**
 * HMA-07.AC4 — the wider walk reaches further without reporting more.
 *
 * Widening a scanner's reach is only worth it if the new ground is quiet on
 * clean trees. The control here is a second copy of the SAME tree with the
 * dot-directories removed: any check ID that fires on the `.claude` copy and
 * not on the control is a finding the widening manufactured, and there must be
 * none. That is the git-free reading of "zero new findings against origin/main
 * on the same fixture" — the pre-fix scanner reported exactly the control set,
 * because none of these directories were entered at all.
 *
 * The symlink test guards HMA-04's confinement (`src/hardening/tracked-fs.ts`,
 * merged in #685), which this change does not edit: entering `.claude` by name
 * must not become a way to follow a directory link out of the tree. Its
 * non-vacuity control is the same payload placed directly under
 * `.claude/skills`, which IS reported.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { MALICIOUS_SKILL, signedBenignSkill } from '../helpers/hma07-skill-fixtures';

type Finding = { checkId: string; passed: boolean; file?: string };

async function writeFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

/** Failing findings as `CHECK-ID@file`, so a new finding on a new path is visible. */
async function failingKeys(targetDir: string): Promise<string[]> {
  const result = await new HardeningScanner().scan({ targetDir, autoFix: false });
  const findings = (result.allFindings || result.findings || []) as Finding[];
  return findings.filter(f => !f.passed).map(f => `${f.checkId}@${f.file}`).sort();
}

/** The shared, deliberately unremarkable body of both trees. */
async function writeCleanProject(root: string): Promise<void> {
  await writeFile(path.join(root, 'README.md'), '# clean project\n');
  await writeFile(path.join(root, 'src', 'index.js'), 'export function add(a, b) { return a + b; }\n');
}

describe('HMA-07.AC4 no false reach', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma07-false-reach-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-07.AC4 a clean tree with .git, .venv, .cache and a benign signed .claude/skills skill produces zero findings the control tree does not', async () => {
    const withDotDirs = path.join(tempDir, 'with');
    const control = path.join(tempDir, 'control');
    await writeCleanProject(withDotDirs);
    await writeCleanProject(control);

    await writeFile(path.join(withDotDirs, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n');
    await writeFile(path.join(withDotDirs, '.venv', 'lib', 'pkg', 'SKILL.md'), MALICIOUS_SKILL);
    await writeFile(path.join(withDotDirs, '.cache', 'pkg', 'SKILL.md'), MALICIOUS_SKILL);
    await writeFile(
      path.join(withDotDirs, '.claude', 'skills', 'markdown-formatter', 'SKILL.md'),
      signedBenignSkill(),
    );

    const withKeys = await failingKeys(withDotDirs);
    const controlKeys = await failingKeys(control);

    expect(withKeys.filter(k => !controlKeys.includes(k))).toEqual([]);
  });

  it('HMA-07.AC4 a symlinked directory under .claude/skills is still not followed', async () => {
    const outside = path.join(tempDir, 'outside');
    await writeFile(path.join(outside, 'evil', 'SKILL.md'), MALICIOUS_SKILL);

    const root = path.join(tempDir, 'linked');
    await writeCleanProject(root);
    await fs.mkdir(path.join(root, '.claude', 'skills'), { recursive: true });
    await fs.symlink(path.join(outside, 'evil'), path.join(root, '.claude', 'skills', 'linked'), 'dir');

    expect((await failingKeys(root)).filter(k => k.includes('linked'))).toEqual([]);

    // Non-vacuous: the identical payload placed directly under `.claude/skills`
    // IS reported, so the empty set above is the link refusal and not a no-op.
    await writeFile(path.join(root, '.claude', 'skills', 'direct', 'SKILL.md'), MALICIOUS_SKILL);
    expect((await failingKeys(root)).filter(k => k.includes('direct')).length).toBeGreaterThan(0);
  });
});
