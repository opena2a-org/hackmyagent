import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SignCryptPlugin } from '../../../src/plugins/signcrypt';

describe('SignCryptPlugin', () => {
  let tmpDir: string;
  let plugin: SignCryptPlugin;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signcrypt-test-'));
    plugin = new SignCryptPlugin();
    await plugin.init();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('scan', () => {
    it('returns empty for directory with no skills/heartbeats', async () => {
      const findings = await plugin.scan(tmpDir);
      expect(findings).toEqual([]);
    });

    it('detects unsigned SKILL.md (SKILL-001)', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# My Skill\nDoes stuff\n', 'utf-8');

      const findings = await plugin.scan(tmpDir);
      const skillFindings = findings.filter((f) => f.id === 'SKILL-001');
      expect(skillFindings.length).toBe(1);
      expect(skillFindings[0].filePath).toBe('SKILL.md');
    });

    it('detects unsigned .skill.md files', async () => {
      fs.mkdirSync(path.join(tmpDir, 'skills'));
      fs.writeFileSync(path.join(tmpDir, 'skills', 'fetch.skill.md'), '# Fetch\nFetches data\n', 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'skills', 'write.skill.md'), '# Write\nWrites data\n', 'utf-8');

      const findings = await plugin.scan(tmpDir);
      const skillFindings = findings.filter((f) => f.id === 'SKILL-001');
      expect(skillFindings.length).toBe(2);
    });

    it('skips already-signed skills', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'SKILL.md'),
        '# My Skill\nDoes stuff\nopena2a_signature: abc123\n',
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      const skillFindings = findings.filter((f) => f.id === 'SKILL-001');
      expect(skillFindings.length).toBe(0);
    });

    it('detects unsigned heartbeat (HEARTBEAT-003)', async () => {
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# Heartbeat\nevery: 4h\n', 'utf-8');

      const findings = await plugin.scan(tmpDir);
      const hbFindings = findings.filter((f) => f.id === 'HEARTBEAT-003');
      expect(hbFindings.length).toBe(1);
    });

    it('detects missing hash pin on heartbeat (HEARTBEAT-002)', async () => {
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# Heartbeat\nevery: 4h\n', 'utf-8');

      const findings = await plugin.scan(tmpDir);
      const pinFindings = findings.filter((f) => f.id === 'HEARTBEAT-002');
      expect(pinFindings.length).toBe(1);
    });

    it('skips heartbeat with existing hash pin', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'HEARTBEAT.md'),
        '# Heartbeat\nevery: 4h\npinned_hash: sha256:abc123\nopena2a_signature: def456\n',
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(0);
    });
  });

  describe('fix', () => {
    it('signs unsigned skill files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# My Skill\nDoes stuff\n', 'utf-8');

      const remediations = await plugin.fix(tmpDir);
      expect(remediations.length).toBeGreaterThan(0);
      expect(remediations[0].findingId).toBe('SKILL-001');

      // Verify signature was added
      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      expect(content).toContain('opena2a_signature:');
      expect(content).toContain('pinned_hash: sha256:');
    });

    it('signs unsigned heartbeat files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'HEARTBEAT.md'), '# Heartbeat\nevery: 4h\n', 'utf-8');

      const remediations = await plugin.fix(tmpDir);
      // Should fix both HEARTBEAT-002 (hash pin) and HEARTBEAT-003 (signature)
      expect(remediations.length).toBeGreaterThanOrEqual(1);

      const content = fs.readFileSync(path.join(tmpDir, 'HEARTBEAT.md'), 'utf-8');
      expect(content).toContain('pinned_hash: sha256:');
      expect(content).toContain('opena2a_signature:');
    });

    it('creates signature records file', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# My Skill\nDoes stuff\n', 'utf-8');

      await plugin.fix(tmpDir);

      const sigFile = path.join(tmpDir, '.opena2a', 'signcrypt', 'signatures.json');
      expect(fs.existsSync(sigFile)).toBe(true);

      const records = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
      expect(records.length).toBeGreaterThan(0);
      expect(records[0].target).toBe('SKILL.md');
    });

    it('dry run does not modify files', async () => {
      const original = '# My Skill\nDoes stuff\n';
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), original, 'utf-8');

      const remediations = await plugin.fix(tmpDir, { dryRun: true });
      expect(remediations.length).toBeGreaterThan(0);

      const content = fs.readFileSync(path.join(tmpDir, 'SKILL.md'), 'utf-8');
      expect(content).toBe(original);
    });
  });

  describe('uninstall', () => {
    it('removes signcrypt directory', async () => {
      fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), '# Skill\n', 'utf-8');
      await plugin.fix(tmpDir);

      const sigDir = path.join(tmpDir, '.opena2a', 'signcrypt');
      expect(fs.existsSync(sigDir)).toBe(true);

      await plugin.uninstall(tmpDir);
      expect(fs.existsSync(sigDir)).toBe(false);
    });
  });
});
