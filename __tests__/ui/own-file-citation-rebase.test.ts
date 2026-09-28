/**
 * #524 — `rebaseOwnFileCitation` rewrites a fix citation of the finding's own
 * target-relative file onto the scan root, and nothing else.
 */
import { describe, it, expect } from 'vitest';
import { rebaseOwnFileCitation } from '../../src/ui/verify-command';

const ROOT = '/work/skill-out';

describe('#524 rebaseOwnFileCitation', () => {
  it('rebases the own-file operand onto the scan root', () => {
    expect(rebaseOwnFileCitation('hackmyagent check SKILL.md', 'SKILL.md', ROOT))
      .toBe('hackmyagent check /work/skill-out/SKILL.md');
  });

  it('keeps the prose after the command', () => {
    expect(rebaseOwnFileCitation('hackmyagent check skills/a/SKILL.md  — re-check it', 'skills/a/SKILL.md', ROOT))
      .toBe('hackmyagent check /work/skill-out/skills/a/SKILL.md  — re-check it');
  });

  it('quotes a rebased path that needs it', () => {
    expect(rebaseOwnFileCitation("hackmyagent check 'my skill.md'", 'my skill.md', ROOT))
      .toBe("hackmyagent check '/work/skill-out/my skill.md'");
  });

  it('treats a $ in the root as text, not as a replacement pattern', () => {
    const out = rebaseOwnFileCitation('hackmyagent check SKILL.md', 'SKILL.md', '/work/a$&b');
    expect(out).toContain('a$&b/SKILL.md');
    expect(out).not.toContain('SKILL.mdSKILL.md');
  });

  it('leaves any other operand as authored', () => {
    for (const text of [
      'hackmyagent check express',
      'hackmyagent harden-soul .',
      'hackmyagent check other/SKILL.md',
      'hackmyagent check SKILL.md.bak',
      'cat SKILL.md',
    ]) {
      expect(rebaseOwnFileCitation(text, 'SKILL.md', ROOT)).toBe(text);
    }
  });

  it('is a no-op without a root, a file, or for an absolute file', () => {
    expect(rebaseOwnFileCitation('hackmyagent check SKILL.md', 'SKILL.md', undefined)).toBe('hackmyagent check SKILL.md');
    expect(rebaseOwnFileCitation('hackmyagent check SKILL.md', undefined, ROOT)).toBe('hackmyagent check SKILL.md');
    expect(rebaseOwnFileCitation('hackmyagent check /abs/SKILL.md', '/abs/SKILL.md', ROOT)).toBe('hackmyagent check /abs/SKILL.md');
  });

  it('leaves the text unchanged when the own path cannot be named', () => {
    const invisible = 'SKI‍LL.md';
    const text = `hackmyagent check ${invisible}`;
    expect(rebaseOwnFileCitation(text, invisible, ROOT)).toBe(text);
  });
});
