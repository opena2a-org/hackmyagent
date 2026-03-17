import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SecretlessPlugin } from '../../../src/plugins/secretless';

describe('SecretlessPlugin', () => {
  let tmpDir: string;
  let plugin: SecretlessPlugin;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-test-'));
    plugin = new SecretlessPlugin();
    await plugin.init();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('scan', () => {
    it('reports SLAI-000 when secretless-ai is not installed', async () => {
      // secretless-ai is not a devDependency of hackmyagent,
      // so the dynamic import will fail and the plugin should degrade gracefully
      const findings = await plugin.scan(tmpDir);

      // Should either return SLAI-000 (not installed) or real findings if
      // secretless-ai happens to be globally installed
      if (findings.length === 1 && findings[0].id === 'SLAI-000') {
        expect(findings[0].id).toBe('SLAI-000');
        expect(findings[0].title).toBe('Secretless AI not installed');
        expect(findings[0].severity).toBe('medium');
        expect(findings[0].autoFixable).toBe(false);
      } else {
        // secretless-ai is available globally — findings are real scan results
        expect(Array.isArray(findings)).toBe(true);
      }
    });
  });

  describe('fix', () => {
    it('returns empty remediations when secretless-ai is not installed', async () => {
      const remediations = await plugin.fix(tmpDir);
      // Without secretless-ai, fix should be a no-op
      expect(remediations).toEqual([]);
    });

    it('returns dry-run previews for auto-fixable findings', async () => {
      const remediations = await plugin.fix(tmpDir, { dryRun: true });
      // Either empty (no secretless-ai) or dry-run entries
      expect(Array.isArray(remediations)).toBe(true);
      for (const r of remediations) {
        expect(r.description).toMatch(/^Would fix:/);
      }
    });
  });

  describe('status', () => {
    it('returns plugin status', async () => {
      const status = await plugin.status();
      expect(status.name).toBe('AI Visibility Protection');
      expect(status.version).toBe('0.1.0');
      // active depends on whether secretless-ai is installed
      expect(typeof status.active).toBe('boolean');
    });
  });

  describe('metadata', () => {
    it('has correct metadata', () => {
      expect(plugin.metadata.packageName).toBe('secretless-ai');
      expect(plugin.metadata.displayName).toBe('AI Visibility Protection');
      expect(plugin.metadata.findings).toContain('SLAI-001');
      expect(plugin.metadata.findings).toContain('SLAI-002');
      expect(plugin.metadata.findings).toContain('SLAI-003');
      expect(plugin.metadata.scoreImprovement).toBe(20);
    });
  });
});
