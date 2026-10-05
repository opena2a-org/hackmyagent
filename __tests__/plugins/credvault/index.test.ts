import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CredVaultPlugin } from '../../../src/plugins/credvault';

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
        JSON.stringify({ apiKey: ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') }),
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
        JSON.stringify({ key: ['sk', '-proj-Qm50BIe8JjiH5tDZHMIuf7HsH6C91YemAR1zNXbHzXSVu7uZWftOLO6F'].join('') }),
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
        'AWS_ACCESS_KEY_ID=' + ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
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
          '{"anthropic": "' + ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') + '",',
          ' "aws": "' + ['AKIA', 'IOSFODNN7EXAMPLE'].join('') + '"}',
        ].join('\n'),
        'utf-8'
      );

      const findings = await plugin.scan(tmpDir);
      const credFindings = findings.filter((f) => f.id === 'CRED-001');
      expect(credFindings.length).toBe(2);
    });

    // #539: the .env key-name rule fired on the name alone, so a line holding
    // no credential at all was reported as a HIGH hardcoded credential.
    describe('.env key-name rule reads the value (#539)', () => {
      const credLines = async (file: string, body: string) => {
        fs.writeFileSync(path.join(tmpDir, file), body, 'utf-8');
        const findings = await plugin.scan(tmpDir);
        return findings.filter((f) => f.id === 'CRED-001').map((f) => f.line);
      };

      it.each([
        ['an empty value', 'API_KEY=\n'],
        ['an empty quoted value', 'API_KEY=""\n'],
        ['an empty value with a trailing comment', 'API_KEY= # set in CI\n'],
        ['a braced reference', 'API_KEY=${OPENAI_API_KEY}\n'],
        ['a braced reference under a vendor key name', 'OPENAI_API_KEY=${OPENAI_API_KEY}\n'],
        ['a bare reference', 'PASSWORD=$FOO\n'],
        ['a quoted reference', 'export DATABASE_URL="${DATABASE_URL}"\n'],
      ])('does not report %s', async (_label, body) => {
        expect(await credLines('.env', body)).toEqual([]);
      });

      it('applies to .env.local as well', async () => {
        expect(await credLines('.env.local', 'API_KEY=\nMY_API_KEY=${MY_API_KEY}\n')).toEqual([]);
      });

      it('still reports a literal value under a credential key name', async () => {
        const body = [
          'API_KEY=',
          'API_KEY=${OPENAI_API_KEY}',
          'API_KEY=a1b2c3d4e5f6',
          'PASSWORD=abc#123',
          'JWT_SECRET=${JWT_SECRET:-fallback-literal}',
          '',
        ].join('\n');
        fs.writeFileSync(path.join(tmpDir, '.env'), body, 'utf-8');
        const findings = (await plugin.scan(tmpDir)).filter((f) => f.id === 'CRED-001');
        expect(findings.map((f) => f.line)).toEqual([3, 4, 5]);
        expect(findings.every((f) => f.severity === 'high')).toBe(true);
        expect(findings[0].title).toBe('Hardcoded credential: API_KEY');
      });
    });
  });

  describe('fix', () => {
    it('replaces credentials with env var references', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') }),
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
        JSON.stringify({ apiKey: ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') }),
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
        JSON.stringify({ apiKey: ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') }),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      // #431 — no store, no key: every store this plugin ever wrote encrypted
      // the literal `{}`, and the key beside it sat ungitignored in the tree.
      const storeDir = path.join(tmpDir, '.opena2a', 'credvault');
      expect(fs.existsSync(storeDir)).toBe(false);
      expect(fs.existsSync(path.join(tmpDir, '.opena2a'))).toBe(false);
    });

    it('dry run does not modify files', async () => {
      const configContent = JSON.stringify({ apiKey: ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('') });
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
      expect(status.name).toBe('Credential Protection');
      expect(status.version).toBe('0.1.0');
    });
  });
});
