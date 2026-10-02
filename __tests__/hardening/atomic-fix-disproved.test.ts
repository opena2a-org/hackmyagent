/**
 * #608 — `atomicFix` is documented as "True if all fixes completed atomically
 * (or rolled back on failure)", but it was derived from the bare attempt flag.
 * A run whose verification pass disproved one fix (`fixed: true`,
 * `fixVerified: false`) still reported `atomicFix: true` in the same JSON
 * document. The fixture is the issue's own: a signed skill whose body no
 * longer matches its signature, so SKILL-004's fix is attempted and disproved,
 * beside a missing .gitignore whose fix lands.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

async function fixture(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-608-'));
  await mkdir(path.join(dir, 'skills', 'demo'), { recursive: true });
  const head = '---\nname: demo\ndescription: demo skill\n---\n# Demo\n\n';
  const signedBody = head + 'filesystem:./ and filesystem: /etc/passwd\n\n';
  const hash = createHash('sha256').update(signedBody.replace(/\n$/, '')).digest('hex');
  await writeFile(
    path.join(dir, 'skills', 'demo', 'SKILL.md'),
    head + 'filesystem: * and filesystem: /etc/passwd\n\n' +
      `<!-- opena2a-guard hash="sha256:${hash}" signed="2026-08-20T00:00:00.000Z" -->`,
  );
  return dir;
}

describe('#608 — atomicFix agrees with the per-finding fix verification', () => {
  it('is false when a fix in the same run was disproved', async () => {
    const dir = await fixture();
    try {
      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const disproved = result.findings.filter((f) => f.fixed && f.fixVerified === false);
      // The scenario must actually hold, or the assertion below proves nothing.
      expect(disproved.length).toBeGreaterThan(0);
      expect(result.atomicFix).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('stays true when every attempted fix is confirmed', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-608-ok-'));
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"ok","version":"1.0.0"}\n');
      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      expect(result.findings.some((f) => f.fixed)).toBe(true);
      expect(result.findings.some((f) => f.fixed && f.fixVerified === false)).toBe(false);
      expect(result.atomicFix).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
