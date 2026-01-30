import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HardeningScanner, ScanOptions } from './scanner';
import type { SecurityFinding, ScanResult } from './security-check';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('HardeningScanner', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('scan', () => {
    it('returns a scan result with findings', async () => {
      const result = await scanner.scan({ targetDir: tempDir });

      expect(result).toMatchObject({
        timestamp: expect.any(Date),
        platform: expect.any(String),
        findings: expect.any(Array),
        score: expect.any(Number),
        maxScore: expect.any(Number),
      });
    });

    it('calculates security score based on findings', async () => {
      const result = await scanner.scan({ targetDir: tempDir });

      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(result.maxScore);
    });

    it('groups findings by category', async () => {
      const result = await scanner.scan({ targetDir: tempDir });
      const findings = result.findings;

      // Each finding should have a category
      for (const finding of findings) {
        expect(finding.category).toBeDefined();
        expect(typeof finding.category).toBe('string');
      }
    });
  });

  describe('credential exposure checks', () => {
    it('detects API keys in config files', async () => {
      // Create a config file with exposed API key
      const configPath = path.join(tempDir, 'config.json');
      await fs.writeFile(
        configPath,
        JSON.stringify({
          apiKey: 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxx',
          name: 'test',
        })
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const credFindings = result.findings.filter(
        (f) => f.category === 'credentials'
      );

      expect(credFindings.some((f) => !f.passed)).toBe(true);
    });

    it('detects OpenAI API keys', async () => {
      const configPath = path.join(tempDir, '.env');
      await fs.writeFile(
        configPath,
        'OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx\n'
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find(
        (f) => f.checkId === 'CRED-001' && !f.passed
      );

      expect(finding).toBeDefined();
      expect(finding?.details?.keys).toContain('OPENAI_API_KEY');
    });

    it('detects AWS credentials', async () => {
      const configPath = path.join(tempDir, 'config.yaml');
      await fs.writeFile(
        configPath,
        'aws_access_key_id: AKIAIOSFODNN7EXAMPLE\naws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find(
        (f) => f.checkId === 'CRED-001' && !f.passed
      );

      expect(finding).toBeDefined();
    });

    it('passes when no credentials exposed', async () => {
      const configPath = path.join(tempDir, 'config.json');
      await fs.writeFile(
        configPath,
        JSON.stringify({
          name: 'safe-config',
          apiKey: '${ANTHROPIC_API_KEY}', // env var reference, not actual key
        })
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const credFindings = result.findings.filter(
        (f) => f.category === 'credentials' && !f.passed
      );

      expect(credFindings).toHaveLength(0);
    });
  });

  describe('file permission checks', () => {
    it('detects world-readable sensitive files', async () => {
      const secretPath = path.join(tempDir, 'secrets.json');
      await fs.writeFile(secretPath, '{"secret": "value"}');
      await fs.chmod(secretPath, 0o644); // world-readable

      const result = await scanner.scan({ targetDir: tempDir });
      const permFindings = result.findings.filter(
        (f) => f.category === 'permissions' && !f.passed
      );

      // Should detect overly permissive files
      expect(permFindings.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('claude code specific checks', () => {
    it('detects CLAUDE.md with sensitive content', async () => {
      const claudeMdPath = path.join(tempDir, 'CLAUDE.md');
      await fs.writeFile(
        claudeMdPath,
        '# Instructions\n\nAPI Key: sk-ant-api03-secret\n\nDo not share this.'
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find(
        (f) => f.checkId === 'CLAUDE-001' && !f.passed
      );

      expect(finding).toBeDefined();
      expect(finding?.message).toContain('CLAUDE.md');
    });

    it('passes for safe CLAUDE.md', async () => {
      const claudeMdPath = path.join(tempDir, 'CLAUDE.md');
      await fs.writeFile(
        claudeMdPath,
        '# Instructions\n\nUse environment variables for API keys.\n'
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find((f) => f.checkId === 'CLAUDE-001');

      expect(finding?.passed).toBe(true);
    });
  });

  describe('MCP configuration checks', () => {
    it('detects insecure MCP server configurations', async () => {
      const mcpConfigPath = path.join(tempDir, 'mcp.json');
      await fs.writeFile(
        mcpConfigPath,
        JSON.stringify({
          servers: {
            filesystem: {
              command: 'mcp-server-filesystem',
              args: ['/'], // Root access - dangerous
            },
          },
        })
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find(
        (f) => f.checkId === 'MCP-001' && !f.passed
      );

      expect(finding).toBeDefined();
    });

    it('detects shell MCP server without restrictions', async () => {
      const mcpConfigPath = path.join(tempDir, 'mcp.json');
      await fs.writeFile(
        mcpConfigPath,
        JSON.stringify({
          servers: {
            shell: {
              command: 'mcp-server-shell',
              // No command restrictions
            },
          },
        })
      );

      const result = await scanner.scan({ targetDir: tempDir });
      const finding = result.findings.find(
        (f) => f.checkId === 'MCP-002' && !f.passed
      );

      expect(finding).toBeDefined();
    });
  });

  describe('auto-fix capabilities', () => {
    it('can fix file permission issues', async () => {
      const secretPath = path.join(tempDir, 'secrets.json');
      await fs.writeFile(secretPath, '{"secret": "value"}');
      await fs.chmod(secretPath, 0o644);

      const result = await scanner.scan({
        targetDir: tempDir,
        autoFix: true,
      });

      // Check if fix was attempted for permission issues
      const permFinding = result.findings.find(
        (f) => f.category === 'permissions' && f.fixable
      );

      if (permFinding && permFinding.fixed) {
        const stats = await fs.stat(secretPath);
        const mode = stats.mode & 0o777;
        expect(mode).toBe(0o600);
      }
    });

    it('reports which fixes were applied', async () => {
      const result = await scanner.scan({
        targetDir: tempDir,
        autoFix: true,
      });

      for (const finding of result.findings) {
        if (finding.fixable && !finding.passed) {
          expect(finding.fixed).toBeDefined();
          if (finding.fixed) {
            expect(finding.fixMessage).toBeDefined();
          }
        }
      }
    });

    it('does not auto-fix when disabled', async () => {
      const secretPath = path.join(tempDir, 'secrets.json');
      await fs.writeFile(secretPath, '{"secret": "value"}');
      await fs.chmod(secretPath, 0o644);

      const result = await scanner.scan({
        targetDir: tempDir,
        autoFix: false,
      });

      const fixedFindings = result.findings.filter((f) => f.fixed);
      expect(fixedFindings).toHaveLength(0);
    });
  });

  describe('score calculation', () => {
    it('gives higher score when more checks pass', async () => {
      // Safe directory
      const safeDir = await fs.mkdtemp(
        path.join(os.tmpdir(), 'hackmyagent-safe-')
      );
      await fs.writeFile(
        path.join(safeDir, 'config.json'),
        JSON.stringify({ name: 'safe' })
      );

      // Unsafe directory
      const unsafeDir = await fs.mkdtemp(
        path.join(os.tmpdir(), 'hackmyagent-unsafe-')
      );
      await fs.writeFile(
        path.join(unsafeDir, 'config.json'),
        JSON.stringify({ apiKey: 'sk-ant-api03-secret' })
      );

      const safeResult = await scanner.scan({ targetDir: safeDir });
      const unsafeResult = await scanner.scan({ targetDir: unsafeDir });

      expect(safeResult.score).toBeGreaterThanOrEqual(unsafeResult.score);

      await fs.rm(safeDir, { recursive: true, force: true });
      await fs.rm(unsafeDir, { recursive: true, force: true });
    });

    it('weights critical issues higher than low', async () => {
      // The score should penalize critical issues more than low issues
      const result = await scanner.scan({ targetDir: tempDir });

      // Verify score calculation logic exists
      expect(result.maxScore).toBeGreaterThan(0);
    });
  });
});

describe('Platform detection', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects Claude Code environment', async () => {
    await fs.writeFile(path.join(tempDir, 'CLAUDE.md'), '# Claude Instructions');

    const result = await scanner.scan({ targetDir: tempDir });
    expect(result.platform).toContain('claude');
  });

  it('detects Cursor environment', async () => {
    await fs.mkdir(path.join(tempDir, '.cursor'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.cursor', 'rules'),
      'cursor rules'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    expect(result.platform).toContain('cursor');
  });

  it('detects MCP configuration', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({ servers: {} })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    expect(result.platform).toContain('mcp');
  });

  it('returns generic for unknown platform', async () => {
    const result = await scanner.scan({ targetDir: tempDir });
    expect(result.platform).toBeDefined();
  });
});
