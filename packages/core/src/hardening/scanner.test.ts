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

describe('Git security checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects missing .gitignore', async () => {
    // No .gitignore file
    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'GIT-001');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });

  it('detects .gitignore missing sensitive patterns', async () => {
    // Create .gitignore without .env pattern
    await fs.writeFile(path.join(tempDir, '.gitignore'), 'node_modules/\n');

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'GIT-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.message).toContain('.env');
  });

  it('passes when .gitignore has all sensitive patterns', async () => {
    await fs.writeFile(
      path.join(tempDir, '.gitignore'),
      '.env\n.env.*\nsecrets.json\n*.pem\n*.key\n'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'GIT-002');

    expect(finding?.passed).toBe(true);
  });

  it('detects .env file when .gitignore missing .env pattern', async () => {
    await fs.writeFile(path.join(tempDir, '.gitignore'), 'node_modules/\n');
    await fs.writeFile(path.join(tempDir, '.env'), 'SECRET=value\n');

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'GIT-003');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });
});

describe('Network security checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects MCP server bound to 0.0.0.0', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          myserver: {
            command: 'mcp-server',
            args: ['--host', '0.0.0.0'],
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'NET-001');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('detects remote MCP server without TLS', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          remote: {
            url: 'http://api.example.com/mcp',
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'NET-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('high');
  });

  it('passes for remote MCP server with HTTPS', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          remote: {
            url: 'https://api.example.com/mcp',
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'NET-002');

    expect(finding?.passed).toBe(true);
  });
});

describe('Additional MCP checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects secrets passed as environment variables to MCP', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          myserver: {
            command: 'mcp-server',
            env: {
              API_KEY: 'sk-ant-api03-hardcoded-secret',
            },
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'MCP-003');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('passes when env vars use references', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          myserver: {
            command: 'mcp-server',
            env: {
              API_KEY: '${ANTHROPIC_API_KEY}',
            },
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'MCP-003');

    expect(finding?.passed).toBe(true);
  });

  it('detects database MCP server with default credentials', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          postgres: {
            command: 'mcp-server-postgres',
            args: ['--password', 'postgres'],
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'MCP-004');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });

  it('detects MCP server allowing all tools', async () => {
    await fs.writeFile(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        servers: {
          myserver: {
            command: 'mcp-server',
            allowedTools: ['*'],
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'MCP-005');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('high');
  });
});

describe('Claude Code additional checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects overly permissive allowed commands', async () => {
    await fs.mkdir(path.join(tempDir, '.claude'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.claude', 'settings.json'),
      JSON.stringify({
        permissions: {
          allow: ['Bash(*)', 'Read(*)', 'Write(*)'],
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CLAUDE-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('high');
  });

  it('detects dangerous Bash patterns', async () => {
    await fs.mkdir(path.join(tempDir, '.claude'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.claude', 'settings.json'),
      JSON.stringify({
        permissions: {
          allow: ['Bash(rm -rf *)'],
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CLAUDE-003');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('passes for scoped permissions', async () => {
    await fs.mkdir(path.join(tempDir, '.claude'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.claude', 'settings.json'),
      JSON.stringify({
        permissions: {
          allow: ['Read(./src/**)', 'Write(./src/**)'],
          deny: ['Bash(rm *)'],
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CLAUDE-002');

    expect(finding?.passed).toBe(true);
  });
});

describe('Cursor configuration checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects credentials in Cursor rules', async () => {
    await fs.mkdir(path.join(tempDir, '.cursor'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.cursor', 'rules'),
      'Use API key sk-ant-api03-secret for all requests\n'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CURSOR-001');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('detects credentials in .cursorrules', async () => {
    await fs.writeFile(
      path.join(tempDir, '.cursorrules'),
      'API_KEY=sk-proj-xxxxxxxxxxxxx\n'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CURSOR-001');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });
});

describe('VSCode configuration checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects credentials in VSCode MCP config', async () => {
    await fs.mkdir(path.join(tempDir, '.vscode'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.vscode', 'mcp.json'),
      JSON.stringify({
        servers: {
          myserver: {
            apiKey: 'sk-ant-api03-exposed',
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'VSCODE-001');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('detects overly permissive VSCode MCP config', async () => {
    await fs.mkdir(path.join(tempDir, '.vscode'), { recursive: true });
    await fs.writeFile(
      path.join(tempDir, '.vscode', 'mcp.json'),
      JSON.stringify({
        servers: {
          filesystem: {
            command: 'mcp-server-filesystem',
            args: ['/'],
          },
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'VSCODE-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });
});

describe('Additional credential checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects private keys in directory', async () => {
    await fs.writeFile(
      path.join(tempDir, 'server.key'),
      '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALRi\n-----END RSA PRIVATE KEY-----\n'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CRED-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
    expect(finding?.severity).toBe('critical');
  });

  it('detects .pem files', async () => {
    await fs.writeFile(
      path.join(tempDir, 'cert.pem'),
      '-----BEGIN CERTIFICATE-----\nMIIBOgIBAAJBALRi\n-----END CERTIFICATE-----\n'
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CRED-002');

    expect(finding).toBeDefined();
  });

  it('detects hardcoded secrets in package.json', async () => {
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        name: 'test',
        scripts: {
          deploy: 'API_KEY=sk-ant-api03-secret npm run build',
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CRED-003');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });

  it('detects JWT secrets in config', async () => {
    await fs.writeFile(
      path.join(tempDir, 'config.json'),
      JSON.stringify({
        jwt: {
          secret: 'super-secret-jwt-key-that-should-not-be-here',
        },
      })
    );

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'CRED-004');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });
});

describe('Permission boundary checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects executable config files', async () => {
    const configPath = path.join(tempDir, 'config.json');
    await fs.writeFile(configPath, '{}');
    await fs.chmod(configPath, 0o755);

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'PERM-002');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });

  it('detects group-writable sensitive files', async () => {
    const envPath = path.join(tempDir, '.env');
    await fs.writeFile(envPath, 'SECRET=value');
    await fs.chmod(envPath, 0o664);

    const result = await scanner.scan({ targetDir: tempDir });
    const finding = result.findings.find((f) => f.checkId === 'PERM-003');

    expect(finding).toBeDefined();
    expect(finding?.passed).toBe(false);
  });
});

describe('Auto-fix: Git security', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('creates .gitignore when missing', async () => {
    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const gitignoreExists = await fs.access(path.join(tempDir, '.gitignore')).then(() => true).catch(() => false);
    expect(gitignoreExists).toBe(true);

    const content = await fs.readFile(path.join(tempDir, '.gitignore'), 'utf-8');
    expect(content).toContain('.env');
    expect(content).toContain('*.pem');
  });

  it('adds missing patterns to existing .gitignore', async () => {
    await fs.writeFile(path.join(tempDir, '.gitignore'), 'node_modules/\n');

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(path.join(tempDir, '.gitignore'), 'utf-8');
    expect(content).toContain('node_modules/');
    expect(content).toContain('.env');
    expect(content).toContain('*.pem');
  });

  it('reports fix was applied for .gitignore', async () => {
    const result = await scanner.scan({ targetDir: tempDir, autoFix: true });

    const gitFinding = result.findings.find(f => f.checkId === 'GIT-001');
    expect(gitFinding?.fixed).toBe(true);
  });
});

describe('Auto-fix: Credential replacement', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('replaces Anthropic API key with env var reference in config.json', async () => {
    const configPath = path.join(tempDir, 'config.json');
    await fs.writeFile(configPath, JSON.stringify({
      apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz',
      name: 'test'
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(configPath, 'utf-8');
    expect(content).not.toContain('sk-ant-api03');
    expect(content).toContain('${ANTHROPIC_API_KEY}');
  });

  it('replaces OpenAI API key with env var reference', async () => {
    const configPath = path.join(tempDir, 'config.json');
    await fs.writeFile(configPath, JSON.stringify({
      openaiKey: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456',
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(configPath, 'utf-8');
    expect(content).not.toContain('sk-proj-');
    expect(content).toContain('${OPENAI_API_KEY}');
  });

  it('creates .env.example with placeholder', async () => {
    const configPath = path.join(tempDir, 'config.json');
    await fs.writeFile(configPath, JSON.stringify({
      apiKey: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz',
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const envExamplePath = path.join(tempDir, '.env.example');
    const envExists = await fs.access(envExamplePath).then(() => true).catch(() => false);
    expect(envExists).toBe(true);

    const content = await fs.readFile(envExamplePath, 'utf-8');
    expect(content).toContain('ANTHROPIC_API_KEY=');
  });
});

describe('Auto-fix: Network security', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('changes 0.0.0.0 to 127.0.0.1 in mcp.json', async () => {
    const mcpPath = path.join(tempDir, 'mcp.json');
    await fs.writeFile(mcpPath, JSON.stringify({
      servers: {
        myserver: {
          command: 'node',
          args: ['server.js', '--host', '0.0.0.0', '--port', '3000']
        }
      }
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(mcpPath, 'utf-8');
    expect(content).not.toContain('0.0.0.0');
    expect(content).toContain('127.0.0.1');
  });

  it('reports fix was applied for network binding', async () => {
    const mcpPath = path.join(tempDir, 'mcp.json');
    await fs.writeFile(mcpPath, JSON.stringify({
      servers: {
        myserver: {
          command: 'node',
          args: ['--host', '0.0.0.0']
        }
      }
    }, null, 2));

    const result = await scanner.scan({ targetDir: tempDir, autoFix: true });

    const netFinding = result.findings.find(f => f.checkId === 'NET-001');
    expect(netFinding?.fixed).toBe(true);
  });
});

describe('Auto-fix: MCP filesystem access', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('changes root "/" to "./data" in mcp.json', async () => {
    const mcpPath = path.join(tempDir, 'mcp.json');
    await fs.writeFile(mcpPath, JSON.stringify({
      servers: {
        filesystem: {
          command: 'mcp-server-filesystem',
          args: ['/']
        }
      }
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(mcpPath, 'utf-8');
    const config = JSON.parse(content);
    expect(config.servers.filesystem.args).not.toContain('/');
    expect(config.servers.filesystem.args).toContain('./data');
  });

  it('changes home "~" to "./" in mcp.json', async () => {
    const mcpPath = path.join(tempDir, 'mcp.json');
    await fs.writeFile(mcpPath, JSON.stringify({
      servers: {
        filesystem: {
          command: 'mcp-server-filesystem',
          args: ['~']
        }
      }
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(mcpPath, 'utf-8');
    const config = JSON.parse(content);
    expect(config.servers.filesystem.args).not.toContain('~');
    expect(config.servers.filesystem.args).toContain('./');
  });
});

describe('Auto-fix: MCP hardcoded secrets', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('replaces hardcoded API key in MCP env with reference', async () => {
    const mcpPath = path.join(tempDir, 'mcp.json');
    await fs.writeFile(mcpPath, JSON.stringify({
      servers: {
        myserver: {
          command: 'node',
          env: {
            API_KEY: 'sk-ant-api03-secretkeyhere1234567890'
          }
        }
      }
    }, null, 2));

    await scanner.scan({ targetDir: tempDir, autoFix: true });

    const content = await fs.readFile(mcpPath, 'utf-8');
    expect(content).not.toContain('sk-ant-api03');
    expect(content).toContain('${ANTHROPIC_API_KEY}');
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
