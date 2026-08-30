/**
 * HMA-07.AC1 — the skill walk reaches `.claude/skills`.
 *
 * `findSkillFiles` skipped every dot-directory except `.openclaw`, `.moltbot`
 * and `.clawdbot` (`src/hardening/scanner.ts:11180-11183` on origin/main
 * 957bb65). `.claude/skills/<name>/SKILL.md` is where skills actually live, so
 * a reverse-shell skill placed there received NO SKILL-* check at all while the
 * byte-identical file one directory over at `skills/<name>/SKILL.md` was
 * reported CRITICAL. That is a false clean on the most common layout.
 *
 * The load-bearing assertion is TWIN PARITY on the failing SKILL-* check IDs,
 * not "some finding appears": the two trees differ only in the name of the
 * directory holding the skill, so any difference in the reported set is the
 * walk, and nothing else. On the pre-fix code the `.claude` set is EMPTY and
 * the plain set has eight IDs in it, which is what gives this suite teeth.
 *
 * The second test is the other half of the contract and must not be loosened
 * into "dot-directories are walked": `.claude` is entered BY NAME. `.git`,
 * `node_modules`, `.venv` and every other dot-directory stay skipped, because a
 * walk that descends into git objects and site-packages buys no skill coverage.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { MALICIOUS_SKILL } from '../helpers/hma07-skill-fixtures';

type Finding = { checkId: string; passed: boolean; file?: string };

async function writeFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

async function failingSkillIds(targetDir: string): Promise<string[]> {
  const result = await new HardeningScanner().scan({ targetDir, autoFix: false });
  const findings = (result.allFindings || result.findings || []) as Finding[];
  return [...new Set(
    findings.filter(f => !f.passed && f.checkId?.startsWith('SKILL-')).map(f => f.checkId),
  )].sort();
}

describe('HMA-07.AC1 static suite walks .claude/skills', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma07-claude-walk-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-07.AC1 a malicious .claude/skills/<name>/SKILL.md fires the same failing SKILL-* checkIds as its skills/<name>/SKILL.md twin', async () => {
    const plainRoot = path.join(tempDir, 'plain');
    const claudeRoot = path.join(tempDir, 'claude');
    await writeFile(path.join(plainRoot, 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);
    await writeFile(path.join(claudeRoot, '.claude', 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);

    const plainIds = await failingSkillIds(plainRoot);
    const claudeIds = await failingSkillIds(claudeRoot);

    // Guard: without this the parity assertion passes on two empty sets.
    expect(plainIds.length).toBeGreaterThan(0);
    expect(claudeIds).toEqual(plainIds);
  });

  it('HMA-07.AC1 .git, node_modules and other dot-directories stay skipped by the skill walk', async () => {
    const root = path.join(tempDir, 'skipped');
    for (const buried of ['.git', 'node_modules', '.venv', '.cache', '.hackmyagent-backup']) {
      await writeFile(path.join(root, buried, 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);
    }

    expect(await failingSkillIds(root)).toEqual([]);

    // Non-vacuous: the same payload IS reported once it sits under `.claude`,
    // so the empty set above is the skip list working, not the scan no-op'ing.
    await writeFile(path.join(root, '.claude', 'skills', 'deploy-helper', 'SKILL.md'), MALICIOUS_SKILL);
    expect((await failingSkillIds(root)).length).toBeGreaterThan(0);
  });
});
