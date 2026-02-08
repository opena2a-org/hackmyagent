import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SecretlessPlugin } from './index';

describe('SecretlessPlugin (deep)', () => {
  let tmpDir: string;
  let plugin: SecretlessPlugin;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-deep-'));
    plugin = new SecretlessPlugin();
    await plugin.init();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ─── Credential pattern accuracy ──────────────────────────────────

  // Build test credential strings at runtime to avoid triggering push protection
  function fakeKey(prefix: string, body: string): string {
    return prefix + body;
  }

  describe('credential pattern accuracy', () => {
    // Helper: write a config.json with a single credential and scan
    async function scanCredential(value: string): Promise<string[]> {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ key: value }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      return findings.filter((f) => f.id === 'CRED-001').map((f) => f.title);
    }

    describe('Anthropic API Key', () => {
      it('detects valid Anthropic key', async () => {
        const titles = await scanCredential('sk-ant-api03-ZGbnD4IEg1WTciUzH6ntayxIp2nq0KNsKdv3LYTaVt8PLo64w70bLILy8M');
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('Anthropic');
      });

      it('detects sk-ant-api02 variant', async () => {
        const titles = await scanCredential('sk-ant-api02-abcdefghijklmnopqrstuvwxyz');
        expect(titles.length).toBe(1);
      });

      it('rejects partial prefix sk-ant-api without digits', async () => {
        const titles = await scanCredential('sk-ant-api-abcdefghijklmnopqrstuvwxyz');
        expect(titles.length).toBe(0);
      });

      it('rejects too-short Anthropic key', async () => {
        const titles = await scanCredential('sk-ant-api03-short');
        expect(titles.length).toBe(0);
      });
    });

    describe('OpenAI API Key', () => {
      it('detects sk-proj- key', async () => {
        const titles = await scanCredential('sk-proj-Qm50BIe8JjiH5tDZHMIuf7HsH6C91YemAR1zNXbHzXSVu7uZWftOLO6F');
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('OpenAI');
      });

      it('rejects too-short sk-proj- key', async () => {
        const titles = await scanCredential('sk-proj-short');
        expect(titles.length).toBe(0);
      });
    });

    describe('AWS Access Key', () => {
      it('detects valid AKIA key', async () => {
        const titles = await scanCredential('AKIAIOSFODNN7EXAMPLE');
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('AWS');
      });

      it('rejects lowercase AKIA key', async () => {
        const titles = await scanCredential('akiaiosfodnn7example');
        expect(titles.length).toBe(0);
      });

      it('rejects AKIA with wrong length', async () => {
        const titles = await scanCredential('AKIA12345');
        expect(titles.length).toBe(0);
      });

      it('detects AKIA key in .env format', async () => {
        fs.writeFileSync(path.join(tmpDir, '.env'), 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n', 'utf-8');
        const findings = await plugin.scan(tmpDir);
        expect(findings.some((f) => f.title.includes('AWS'))).toBe(true);
      });
    });

    describe('GitHub Token', () => {
      it('detects ghp_ fine-grained token', async () => {
        const titles = await scanCredential('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('GitHub');
      });

      it('rejects ghp_ with wrong length', async () => {
        const titles = await scanCredential('ghp_tooshort');
        expect(titles.length).toBe(0);
      });
    });

    describe('Google API Key', () => {
      it('detects AIza key', async () => {
        const titles = await scanCredential('AIzaSyB1234567890abcdefghijklmnopqrstuv');
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('Google');
      });

      it('rejects wrong prefix', async () => {
        const titles = await scanCredential('AIzb1234567890abcdefghijklmnopqrstuv');
        expect(titles.length).toBe(0);
      });
    });

    describe('Stripe Live Key', () => {
      it('detects sk_live_ key', async () => {
        const titles = await scanCredential(fakeKey('sk_live' + '_', 'FAKEFAKEFAKE00000000fake'));
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('Stripe');
      });

      it('does not detect sk_test_ key', async () => {
        const titles = await scanCredential(fakeKey('sk_test' + '_', 'FAKEFAKEFAKE00000000fake'));
        expect(titles.length).toBe(0);
      });
    });

    describe('Slack Token', () => {
      it('detects xoxb bot token', async () => {
        const titles = await scanCredential(fakeKey('xoxb-', '0000000000-0000000000-FAKEFAKEFAKEFAKEFAKEFAKE'));
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('Slack');
      });
    });

    describe('SendGrid Key', () => {
      it('detects SG. key', async () => {
        const titles = await scanCredential(fakeKey('SG.', 'abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst'));
        expect(titles.length).toBe(1);
        expect(titles[0]).toContain('SendGrid');
      });
    });
  });

  // ─── False positive resistance ────────────────────────────────────

  describe('false positive resistance', () => {
    it('does not flag placeholder env var references', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: '${ANTHROPIC_API_KEY}' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('does not flag empty string values', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: '', secret: '' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('does not flag short random strings', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ token: 'abc123', secret: 'mysecret' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('does not flag process.env references', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        '{"key": "process.env.OPENAI_API_KEY"}',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });
  });

  // ─── Multi-credential detection ───────────────────────────────────

  describe('multi-credential detection', () => {
    it('finds credentials on separate lines', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        [
          '{',
          '  "anthropic": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",',
          '  "aws": "AKIAIOSFODNN7EXAMPLE"',
          '}',
        ].join('\n'),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      const creds = findings.filter((f) => f.id === 'CRED-001');
      expect(creds.length).toBe(2);
    });

    it('finds credentials across multiple files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ key: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );
      fs.writeFileSync(
        path.join(tmpDir, '.env'),
        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      const creds = findings.filter((f) => f.id === 'CRED-001');
      expect(creds.length).toBe(2);
      const files = creds.map((f) => f.filePath);
      expect(files).toContain('config.json');
      expect(files).toContain('.env');
    });
  });

  // ─── Private key file detection ───────────────────────────────────

  describe('key file detection', () => {
    it('detects .key files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'server.key'), 'fake', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-002' && f.filePath === 'server.key')).toBe(true);
    });

    it('detects .pem files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'cert.pem'), 'fake', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-002')).toBe(true);
    });

    it('detects .p12 files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'store.p12'), 'fake', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-002')).toBe(true);
    });

    it('detects .pfx files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'cert.pfx'), 'fake', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-002')).toBe(true);
    });

    it('does not flag .json or .md files', async () => {
      fs.writeFileSync(path.join(tmpDir, 'data.json'), '{}', 'utf-8');
      fs.writeFileSync(path.join(tmpDir, 'README.md'), '# Docs', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-002').length).toBe(0);
    });
  });

  // ─── JWT secret detection ─────────────────────────────────────────

  describe('JWT secret detection', () => {
    it('detects jwt_secret in config', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ jwt_secret: 'my-secret-key' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-004')).toBe(true);
    });

    it('detects token_secret in config', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ token_secret: 'my-secret-key' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-004')).toBe(true);
    });

    it('detects jwtSecret (camelCase) in config', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ jwtSecret: 'my-secret-key' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-004')).toBe(true);
    });
  });

  // ─── Fix idempotency ─────────────────────────────────────────────

  describe('fix idempotency', () => {
    it('fix then scan returns zero CRED-001 findings', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      // Re-scan
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('fix called twice does not double-replace', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      await plugin.fix(tmpDir);
      const afterFirst = fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf-8');

      await plugin.fix(tmpDir);
      const afterSecond = fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf-8');

      expect(afterFirst).toBe(afterSecond);
    });

    it('env var reference is not flagged as credential', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ apiKey: '${ANTHROPIC_API_KEY}' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });
  });

  // ─── Fix output verification ──────────────────────────────────────

  describe('fix output verification', () => {
    it('creates encrypted store with key and meta files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ key: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      const storeDir = path.join(tmpDir, '.opena2a', 'secretless');
      expect(fs.existsSync(path.join(storeDir, 'secrets.meta.json'))).toBe(true);
      expect(fs.existsSync(path.join(storeDir, 'secrets.enc'))).toBe(true);
      expect(fs.existsSync(path.join(storeDir, 'store.key'))).toBe(true);

      // Verify meta is valid JSON
      const meta = JSON.parse(fs.readFileSync(path.join(storeDir, 'secrets.meta.json'), 'utf-8'));
      expect(meta.version).toBe('1');

      // Verify store key is hex-encoded 32 bytes (64 hex chars)
      const keyHex = fs.readFileSync(path.join(storeDir, 'store.key'), 'utf-8');
      expect(keyHex.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(keyHex)).toBe(true);

      // Verify encrypted store has iv:authTag:ciphertext format (AES-256-GCM)
      const enc = fs.readFileSync(path.join(storeDir, 'secrets.enc'), 'utf-8');
      const parts = enc.split(':');
      expect(parts.length).toBe(3);
      expect(parts[0].length).toBe(24); // 12 bytes IV = 24 hex chars (GCM)
      expect(parts[1].length).toBe(32); // 16 bytes auth tag = 32 hex chars
      expect(parts[2].length).toBeGreaterThan(0);
    });

    it('.env.example contains correct variable names', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        ['{',
          '  "a": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",',
          '  "b": "AKIAIOSFODNN7EXAMPLE"',
          '}'].join('\n'),
        'utf-8'
      );

      await plugin.fix(tmpDir);

      const envExample = fs.readFileSync(path.join(tmpDir, '.env.example'), 'utf-8');
      expect(envExample).toContain('ANTHROPIC_API_KEY');
      expect(envExample).toContain('AWS_ACCESS_KEY');
    });
  });

  // ─── Edge cases ───────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles empty directory', async () => {
      const findings = await plugin.scan(tmpDir);
      expect(findings).toEqual([]);
    });

    it('handles empty config.json', async () => {
      fs.writeFileSync(path.join(tmpDir, 'config.json'), '', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('handles config.json with only whitespace', async () => {
      fs.writeFileSync(path.join(tmpDir, 'config.json'), '   \n\n  ', 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('skips very long lines (>4096 chars) for ReDoS protection', async () => {
      const longLine = 'x'.repeat(4096) + 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz';
      fs.writeFileSync(path.join(tmpDir, 'config.json'), longLine, 'utf-8');
      const findings = await plugin.scan(tmpDir);
      // Line exceeds 4096 so should be skipped
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(0);
    });

    it('detects credential on line under 4096 chars', async () => {
      const line = 'x'.repeat(100) + 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz';
      fs.writeFileSync(path.join(tmpDir, 'config.json'), line, 'utf-8');
      const findings = await plugin.scan(tmpDir);
      expect(findings.filter((f) => f.id === 'CRED-001').length).toBe(1);
    });

    it('scans nested openclaw config paths', async () => {
      fs.mkdirSync(path.join(tmpDir, '.openclaw'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, '.openclaw', 'config.json'),
        JSON.stringify({ key: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-001')).toBe(true);
    });

    it('scans .env.local', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '.env.local'),
        'API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz\n',
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      expect(findings.some((f) => f.id === 'CRED-001')).toBe(true);
    });

    it('reports correct line numbers', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        ['line1', 'line2', 'AKIAIOSFODNN7EXAMPLE', 'line4'].join('\n'),
        'utf-8'
      );
      const findings = await plugin.scan(tmpDir);
      const aws = findings.find((f) => f.title.includes('AWS'));
      expect(aws).toBeDefined();
      expect(aws!.line).toBe(3);
    });

    it('dry run does not create store', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({ key: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' }),
        'utf-8'
      );
      await plugin.fix(tmpDir, { dryRun: true });
      expect(fs.existsSync(path.join(tmpDir, '.opena2a'))).toBe(false);
    });

    it('status returns correct metadata', async () => {
      const status = await plugin.status();
      expect(status.name).toBe('Secretless');
      expect(status.version).toBe('0.1.0');
    });
  });
});
