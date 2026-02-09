import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CredVaultPlugin } from './index';

describe('CredVaultPlugin', () => {
  let tmpDir: string;
  let plugin: CredVaultPlugin;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'credvault-test-'));
    plugin = new CredVaultPlugin();
    await plugin.init();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('scan', () => {
    it('returns empty findings for clean directory', async () => {
      const findings = await plugin.scan(tmpDir);
      expect(findings).toEqual([]);
    });

    it('detects Anthropic API key in config.json (CRED-001)', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(1);
      expect(findings[0].id).toBe('CRED-001');
      expect(findings[0].title).toContain('Anthropic');
      expect(findings[0].severity).toBe('critical');
    });

    it('detects OpenAI API key (CRED-001)', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ key: 'sk-proj-Qm50BIe8JjiH5tDZHMIuf7HsH6C91YemAR1zNXbHzXSVu7uZWftOLO6F' }),
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(1);
      expect(findings[0].id).toBe('CRED-001');
      expect(findings[0].title).toContain('OpenAI');
    });

    it('detects AWS access key (CRED-001)', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '.env'),
        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      expect(findings.length).toBe(1);
      expect(findings[0].id).toBe('CRED-001');
      expect(findings[0].title).toContain('AWS');
    });

    it('detects private key files (CRED-002)', async () => {
      fs.writeFileSync(path.join(tmpDir, 'server.key'), 'fake-key', 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'cert.pem'), 'fake-cert', 'utf-8');

      const findings = await plugin.scan(tmpDir);
      const keyFindings = findings.filter((f) => f.id === 'CRED-002');
      expect(keyFindings.length).toBe(2);
    });

    it('detects JWT secrets in config (CRED-004)', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ jwt_secret: 'my-secret-key-123' }),
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      const jwtFindings = findings.filter((f) => f.id === 'CRED-004');
      expect(jwtFindings.length).toBe(1);
    });

    it('handles multiple credentials in one file', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        [
          '{"anthropic": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",',
          ' "aws": "AKIAIOSFODNN7EXAMPLE"}',
        ].join('\n'),
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      const credFindings = findings.filter((f) => f.id === 'CRED-001');
      expect(credFindings.length).toBe(2);
    });
  });

  describe('fix', () => {
    it('replaces credentials with env var references', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      const remediations = await plugin.fix(tmpDir);
      expect(remediations.length).toBeGreaterThan(0);
      expect(remediations[0].findingId).toBe('CRED-001');

      // Verify credential is replaced
      const content = fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf-8');
      expect(content).not.toContain('sk-ant-api03');
      expect(content).toContain('${ANTHROPIC_API_KEY}');
    });

    it('creates .env.example file', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      const envExample = path.join(tmpDir, '.env.example');
      expect(fs.existsSync(envExample)).toBe(true);
      const content = fs.readFileSync(envExample, 'utf-8');
      expect(content).toContain('ANTHROPIC_API_KEY');
    });

    it('creates encrypted store directory', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      const storeDir = path.join(tmpDir, '.opena2a', 'credvault');
      expect(fs.existsSync(storeDir)).toBe(true);
      expect(fs.existsSync(path.join(storeDir, 'secrets.meta.json'))).toBe(true);
    });

    it('dry run does not modify files', async () => {
      const configContent = JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' });
      fs.writeFileSync(path.join(tmpDir, 'config.json'), configContent, 'utf-8');

      const remediations = await plugin.fix(tmpDir, { dryRun: true });
      expect(remediations.length).toBeGreaterThan(0);

      // File should be unchanged
      const content = fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf-8');
      expect(content).toBe(configContent);
    });

    it('returns empty for clean directory', async () => {
      const remediations = await plugin.fix(tmpDir);
      expect(remediations).toEqual([]);
    });
  });

  describe('status', () => {
    it('returns plugin status', async () => {
      const status = await plugin.status();
      expect(status.name).toBe('CredVault');
      expect(status.version).toBe('0.1.0');
    });
  });
});
