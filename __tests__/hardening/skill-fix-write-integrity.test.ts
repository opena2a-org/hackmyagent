// A scan buffer must never be a write source (SKILL-004).
//
// `checkSkillFiles` splits the file into `lines` with every line over
// MAX_LINE_LENGTH (10 KB) truncated, so a catastrophic regex cannot be fed an
// unbounded string. That buffer is a SAFETY structure, not the document.
//
// SKILL-004's auto-fix narrows `filesystem:*` capabilities. Rebuilding the
// file from `lines` therefore wrote the TRUNCATED document back over the real
// one: a 12072-byte SKILL.md returned as 10059 bytes — 2013 bytes destroyed —
// with no finding and no warning, because nothing downstream compares sizes.
//
// The second half is worse and is why one test covers both. `lines` is split
// at the top of the check, BEFORE SKILL-001 appends its `opena2a-guard`
// signature block. So writing from it also erased a signature that the SAME
// run had just successfully written, leaving the run's own output
// inconsistent with the file on disk.
//
// This behaviour was correct in the code but completely unguarded: reverting
// the rebuild to `lines.join('\n')` left the entire suite green. That is how
// this class ships.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const dirs: string[] = [];
const MAX_LINE_LENGTH = 10000;

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/**
 * A skill whose body carries BOTH an over-long line (so the scan buffer
 * truncates) and a broad filesystem capability (so SKILL-004 rewrites and
 * writes). Without both, the write path is never reached with a lossy buffer
 * and the assertions pass vacuously.
 */
function makeSkill(): { dir: string; skillPath: string; longLine: string } {
  const dir = mkdtempSync(join(tmpdir(), 'hma-skillwrite-'));
  dirs.push(dir);
  mkdirSync(join(dir, 'skills', 'demo'), { recursive: true });
  const skillPath = join(dir, 'skills', 'demo', 'SKILL.md');

  const longLine = `<!-- ${'x'.repeat(MAX_LINE_LENGTH + 2000)} -->`;
  const body = [
    '---',
    'name: demo',
    'capabilities:',
    '  - filesystem:*',
    '---',
    '',
    '# Demo skill',
    longLine,
    '',
    'Trailing content that must survive the fix.',
    '',
  ].join('\n');

  writeFileSync(skillPath, body);
  writeFileSync(join(dir, 'package.json'), '{"name":"skillwrite","version":"1.0.0"}\n');
  return { dir, skillPath, longLine };
}

describe('SKILL-004 rebuilds the write from the document, not the scan buffer', { timeout: 240_000 }, () => {
  it('does not truncate an over-long line, and keeps the signature written this run', async () => {
    const { dir, skillPath, longLine } = makeSkill();
    const before = readFileSync(skillPath, 'utf8');
    const beforeSize = statSync(skillPath).size;

    // Precondition: the fixture really does exceed the scan buffer's cap.
    expect(longLine.length).toBeGreaterThan(MAX_LINE_LENGTH);
    expect(beforeSize).toBeGreaterThan(MAX_LINE_LENGTH);

    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    const after = readFileSync(skillPath, 'utf8');

    // Precondition: the SKILL-004 fix actually ran and rewrote the file.
    expect(after).not.toBe(before);
    expect(after).not.toMatch(/filesystem:\s*\*/i);

    // The contract. Reverting the rebuild to `lines.join('\n')` silently
    // discards everything past 10 KB on that line.
    expect(after).toContain(longLine);
    expect(after).toContain('Trailing content that must survive the fix.');
    expect(statSync(skillPath).size).toBeGreaterThanOrEqual(beforeSize);

    // And the signature SKILL-001 appended earlier in this same run is still
    // there — the scan buffer was split before it existed.
    expect(after).toMatch(/<!-- opena2a-guard hash="sha256:/);
  });
});
