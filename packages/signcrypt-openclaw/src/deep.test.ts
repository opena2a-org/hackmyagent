import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SignCryptPlugin } from './index';

describe('SignCryptPlugin (deep)', () => {
  let tmpDir: string;
  let plugin: SignCryptPlugin;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signcrypt-deep-'));
    plugin = new SignCryptPlugin();
    await plugin.init();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ─── Signature idempotency (critical: no double-signing) ─────────

  describe('signature idempotency', () => {
    it('fix then scan returns zero findings', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# My Skill\nDoes stuff\n', 'utf-8');

      await plugin.fix(tmpDir);
      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(0);
    });

    it('fix called twice does not double-append signature block', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# My Skill\nDoes stuff\n', 'utf-8');

      await plugin.fix(tmpDir);
      const afterFirst = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      const sigCount1 = (afterFirst.match(/opena2a_signature:/g) || []).length;

      await plugin.fix(tmpDir);
      const afterSecond = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      const sigCount2 = (afterSecond.match(/opena2a_signature:/g) || []).length;

      expect(sigCount1).toBe(1);
      expect(sigCount2).toBe(1);
    });

    it('fix called twice does not double-append hash pin', async () => {
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# HB\nevery: 4h\n', 'utf-8');

      await plugin.fix(tmpDir);
      await plugin.fix(tmpDir);

      const content = fs.readFileSync(path.join(tmpDir, 'HEARTBEAT.md'), 'utf-8');
      const pinCount = (content.match(/pinned_hash:/g) || []).length;
      expect(pinCount).toBe(1);
    });

    it('fix returns empty remediations on second call', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');

      const first = await plugin.fix(tmpDir);
      expect(first.length).toBeGreaterThan(0);

      const second = await plugin.fix(tmpDir);
      expect(second.length).toBe(0);
    });
  });

  // ─── Signature block format ───────────────────────────────────────

  describe('signature block format', () => {
    it('appended block contains all required fields', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      await plugin.fix(tmpDir);

      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      expect(content).toContain('<!-- opena2a:signcrypt -->');
      expect(content).toContain('pinned_hash: sha256:');
      expect(content).toContain('opena2a_signature:');
      expect(content).toContain('signer:');
      expect(content).toContain('signed_at:');
      expect(content).toContain('expires_at:');
      expect(content).toContain('<!-- /opena2a:signcrypt -->');
    });

    it('pinned_hash is a valid hex SHA-256 (64 chars)', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      await plugin.fix(tmpDir);

      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      const match = content.match(/pinned_hash: sha256:([a-f0-9]+)/);
      expect(match).not.toBeNull();
      expect(match![1].length).toBe(64);
    });

    it('expires_at is in the future', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      await plugin.fix(tmpDir);

      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      const match = content.match(/expires_at: (.+)/);
      expect(match).not.toBeNull();
      const expiresAt = new Date(match![1]);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
    });
  });

  // ─── Signature records ────────────────────────────────────────────

  describe('signature records', () => {
    it('creates signatures.json with correct structure', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      await plugin.fix(tmpDir);

      const sigFile = path.join(tmpDir, '.opena2a', 'signcrypt', 'signatures.json');
      expect(fs.existsSync(sigFile)).toBe(true);

      const records = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
      expect(Array.isArray(records)).toBe(true);
      expect(records.length).toBe(1);
      expect(records[0].target).toBe('SKILL.md');
      expect(records[0].hash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(records[0].signedAt).toBeTruthy();
    });

    it('signature records deduplicate by target', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Original\n', 'utf-8');
      await plugin.fix(tmpDir);

      // Modify and re-sign (simulate content update)
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Updated\n', 'utf-8');
      await plugin.fix(tmpDir);

      const sigFile = path.join(tmpDir, '.opena2a', 'signcrypt', 'signatures.json');
      const records = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
      const skillRecords = records.filter((r: { target: string }) => r.target === 'SKILL.md');
      expect(skillRecords.length).toBe(1);
    });

    it('handles multiple files in signature records', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# HB\nevery: 4h\n', 'utf-8');
      await plugin.fix(tmpDir);

      const sigFile = path.join(tmpDir, '.opena2a', 'signcrypt', 'signatures.json');
      const records = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
      const targets = records.map((r: { target: string }) => r.target);
      expect(targets).toContain('SKILL.md');
      expect(targets).toContain('HEARTBEAT.md');
    });
  });

  // ─── File discovery ───────────────────────────────────────────────

  describe('file discovery', () => {
    it('finds SKILL.md in root', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Root\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.filePath === 'SKILL.md')).toBe(true);
    });

    it('finds *.skill.md in subdirectories', async () => {
      fs.mkdirSync(path.join(tmpDir, 'skills'));
      fs.writeFileSync(path.join(tmpDir, 'skills', 'fetch.skill.md'), '# Fetch\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.filePath?.includes('fetch.skill.md'))).toBe(true);
    });

    it('finds HEARTBEAT.md', async () => {
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# HB\nevery: 4h\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'HEARTBEAT-003')).toBe(true);
      expect(findings.some((f) => f.id === 'HEARTBEAT-002')).toBe(true);
    });

    it('skips node_modules', async () => {
      fs.mkdirSync(path.join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'node_modules', 'pkg', 'SKILL.md'), '# Skip\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.filePath?.includes('node_modules')).length).toBe(0);
    });

    it('skips .git directory', async () => {
      fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, '.git', 'hooks', 'SKILL.md'), '# Skip\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.filePath?.includes('.git')).length).toBe(0);
    });
  });

  // ─── Already-signed files ─────────────────────────────────────────

  describe('already-signed detection', () => {
    it('does not report SKILL-001 for file with opena2a_signature:', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'SKILL.md'),
        '# Signed\nopena2a_signature: abc123\n',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'SKILL-001').length).toBe(0);
    });

    it('does not report SKILL-001 for file with BEGIN SIGNATURE block', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'SKILL.md'),
        '# Signed\n-----BEGIN SIGNATURE-----\ndata\n-----END SIGNATURE-----\n',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'SKILL-001').length).toBe(0);
    });

    it('does not report HEARTBEAT-002 when pinned_hash exists', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'HEARTBEAT.md'),
        '# HB\npinned_hash: sha256:abc\nopena2a_signature: def\n',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'HEARTBEAT-002').length).toBe(0);
    });
  });

  // ─── Edge cases ───────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles empty SKILL.md', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'SKILL-001')).toBe(true);
    });

    it('handles SKILL.md with only whitespace', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '   \n\n  ', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'SKILL-001')).toBe(true);
    });

    it('handles directory with no skill or heartbeat files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'README.md'), '# Nothing\n', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(0);
    });

    it('handles many skill files (50+)', async () => {
      fs.mkdirSync(path.join(tmpDir, 'skills'));
      for (let i = 0; i < 50; i++) {
        fs.writeFileSync(
          path.join(tmpDir, 'skills', `skill-${i}.skill.md`),
          `# Skill ${i}\n`,
          'utf-8'
        );
      }
      const findings = await plugin.scan(tmpDir);
      const unsigned = findings.filter((f) => f.id === 'SKILL-001');
      expect(unsigned.length).toBe(50);
    });

    it('fix handles many files without error', async () => {
      fs.mkdirSync(path.join(tmpDir, 'skills'));
      for (let i = 0; i < 20; i++) {
        fs.writeFileSync(
          path.join(tmpDir, 'skills', `skill-${i}.skill.md`),
          `# Skill ${i}\n`,
          'utf-8'
        );
      }
      const remediations = await plugin.fix(tmpDir);
      expect(remediations.length).toBeGreaterThan(0);

      // All should now be signed
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'SKILL-001').length).toBe(0);
    });

    it('original content is preserved after signing', async () => {
      const original = '# My Agent\n\nThis skill does important things.\n\n## Capabilities\n- filesystem:read\n';
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), original, 'utf-8');
      await plugin.fix(tmpDir);

      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      expect(content.startsWith(original)).toBe(true);
    });
  });

  // ─── Uninstall ────────────────────────────────────────────────────

  describe('uninstall', () => {
    it('removes signcrypt directory', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# S\n', 'utf-8');
      await plugin.fix(tmpDir);
      expect(fs.existsSync(path.join(tmpDir, '.opena2a', 'signcrypt'))).toBe(true);

      await plugin.uninstall(tmpDir);
      expect(fs.existsSync(path.join(tmpDir, '.opena2a', 'signcrypt'))).toBe(false);
    });

    it('uninstall is safe on directory without signcrypt data', async () => {
      // Should not throw
      await plugin.uninstall(tmpDir);
      await plugin.uninstall(path.join(tmpDir, 'nonexistent'));
    });
  });

  // ─── Dry run ──────────────────────────────────────────────────────

  describe('dry run', () => {
    it('does not modify any files', async () => {
      const original = '# Skill\n';
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), original, 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# HB\nevery: 4h\n', 'utf-8');

      const remediations = await plugin.fix(tmpDir, { dryRun: true });
      expect(remediations.length).toBeGreaterThan(0);

      // Files untouched
      expect(fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8')).toBe(original);
      expect(fs.existsSync(path.join(tmpDir, '.opena2a'))).toBe(false);
    });

    it('dry run reports all fixable findings', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# S\n', 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# HB\nevery: 4h\n', 'utf-8');

      const remediations = await plugin.fix(tmpDir, { dryRun: true });
      const ids = remediations.map((r) => r.findingId);
      expect(ids).toContain('SKILL-001');
      expect(ids).toContain('HEARTBEAT-002');
      expect(ids).toContain('HEARTBEAT-003');
    });
  });
});
