import { describe, it, expect } from 'vitest';
import { CredentialContextAnalyzer } from '../../src/semantic/structural/credential-context';
import type { AnalysisFile } from '../../src/semantic/types';

const analyzer = new CredentialContextAnalyzer();

function makeFile(path: string, content: string, type: AnalysisFile['type'] = 'config_file'): AnalysisFile {
  return { path, type, content, truncated: false };
}

describe('CredentialContextAnalyzer', () => {
  describe('URL passwords', () => {
    it('detects postgres URL with embedded password', () => {
      const file = makeFile('.env', 'DATABASE_URL=postgres://admin:password123@localhost:5432/mydb', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-001')).toBe(true);
      expect(findings[0].severity).toBe('high');
    });

    it('detects redis URL with embedded password', () => {
      const file = makeFile('.env', 'REDIS_URL=redis://default:MyR3d!sP@ss@redis.example.com:6379', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-001')).toBe(true);
    });

    it('detects mongodb URL with embedded password', () => {
      const file = makeFile('config.json', '{"uri": "mongodb://root:mongopass456@mongo.example.com:27017/app"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-001')).toBe(true);
    });

    it('detects password containing @ symbol', () => {
      const file = makeFile('.env', 'DATABASE_URL=postgres://admin:P@ssw0rd123!@db.prod.example.com:5432/production', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-001')).toBe(true);
    });

    it('ignores URLs without credentials', () => {
      const file = makeFile('.env', 'API_URL=https://api.example.com/v1', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-001')).toHaveLength(0);
    });

    it('ignores URLs with env var references in password', () => {
      const file = makeFile('.env', 'DATABASE_URL=postgres://admin:${DB_PASSWORD}@localhost:5432/mydb', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-001')).toHaveLength(0);
    });

    it('redacts every occurrence of the password from evidence content (regression: H1)', () => {
      // Adversarial reviewer found that an earlier split-on-`:pw@` redaction
      // missed bare-password substrings appearing on the same line as the URL
      // (e.g., a comment or sibling assignment). Verify the password is
      // redacted EVERYWHERE in evidence.lines[].content, not just the URL slot.
      const file = makeFile(
        'config.yaml',
        'DATABASE_URL=postgres://admin:supersecret123@host  # password is supersecret123',
        'config_file'
      );
      const findings = analyzer.analyze([file]);
      const sem = findings.find((f) => f.id === 'SEM-CRED-001');
      expect(sem).toBeDefined();
      const content = sem?.evidence?.kind === 'positive' ? sem.evidence.lines[0]?.content : undefined;
      expect(content).toBeDefined();
      expect(content).not.toContain('supersecret123');
      expect(content).toContain('[REDACTED]');
    });
  });

  describe('generic tokens via key-name heuristics', () => {
    it('detects hardcoded secret in JSON config', () => {
      const file = makeFile('config.json', '{"api_secret": "aB3dE5fG7hI9jK1mN3pQ5"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-002')).toBe(true);
    });

    it('detects hardcoded token in YAML config', () => {
      const file = makeFile('config.yaml', 'api_token: mySecretToken12345678', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-002')).toBe(true);
    });

    it('detects secrets in .env files', () => {
      const file = makeFile('.env', 'JWT_SECRET=super-secret-jwt-key-2024', 'env_file');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-002')).toBe(true);
    });

    it('ignores env var references', () => {
      const file = makeFile('config.json', '{"api_secret": "${API_SECRET}"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
    });

    it('ignores short/non-secret values', () => {
      const file = makeFile('config.json', '{"port": "3000"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
    });

    it('ignores boolean values', () => {
      const file = makeFile('config.json', '{"auth": "true"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
    });

    it('ignores placeholder values', () => {
      const file = makeFile('config.json', '{"api_key": "your-api-key-here"}', 'config_file');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
    });

    // The reported complaint survived the AST-CRED-003 fix through THIS
    // detector. `detectGenericTokens` carried three byte-identical copies of
    // the value gate and none of them had an entropy floor, so a form blank
    // next to a secret-shaped key name was still a credential — and in an
    // instruction file it scored CRITICAL, louder than the finding that
    // started the unit. All three shapes are covered because all three copies
    // were wrong; they now share one `looksLikeSecretValue`.
    describe('form blanks are not secret values (the reported complaint, via SEM-CRED-002)', () => {
      const BLANK = '_'.repeat(47);

      it('does not flag a form blank in a CLAUDE.md onboarding checklist', () => {
        const file = makeFile(
          'CLAUDE.md',
          `# Onboarding\n\nFill these in on your first day:\n\npassword: ${BLANK}\napi_key: ${BLANK}\n`,
          'agent_instructions',
        );
        const findings = analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002');
        expect(
          findings,
          `a form blank must not score CRITICAL. Got: ${findings.map((f) => `${f.severity} ${f.title}`).join(', ')}`,
        ).toHaveLength(0);
      });

      it('does not flag a form blank in a JSON pair', () => {
        const file = makeFile('config/app.json', `{\n  "password": "${BLANK}",\n  "api_key": "${BLANK}"\n}\n`);
        expect(analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
      });

      it('does not flag a form blank in a YAML pair', () => {
        const file = makeFile('deploy/values.yaml', `db_password: ${BLANK}\n`);
        expect(analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
      });

      it('does not flag a form blank in a KEY=VALUE line', () => {
        const file = makeFile('.env.template', `PASSWORD=${BLANK}\nAPI_KEY=${BLANK}\n`, 'env_file');
        expect(analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
      });

      it('does not flag a dot-leader run', () => {
        const file = makeFile('config.yaml', `api_token: ${'_='.repeat(25)}\n`);
        expect(analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002')).toHaveLength(0);
      });

      // NO-DETECTION-LOSS controls. The three shapes above must keep firing on
      // real values, or the fix traded a false positive for a blind spot.
      it('still flags a real secret in each of the three shapes', () => {
        const real = 'aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG';
        const shapes: Array<[string, string, AnalysisFile['type']]> = [
          ['config/app.json', `{ "password": "${real}" }`, 'config_file'],
          ['deploy/values.yaml', `db_password: ${real}`, 'config_file'],
          ['.env.local', `PASSWORD=${real}`, 'env_file'],
        ];
        for (const [path, content, type] of shapes) {
          const findings = analyzer.analyze([makeFile(path, content, type)]);
          expect(
            findings.filter((f) => f.id === 'SEM-CRED-002').length,
            `${path} must still report a real secret`,
          ).toBeGreaterThan(0);
        }
      });

      it('still flags a real secret sitting beside a form blank', () => {
        const file = makeFile(
          'config.yaml',
          `placeholder_token: ${BLANK}\napi_secret: aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG\n`,
        );
        const findings = analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-002');
        expect(findings.length, 'the blank must not mask the real secret below it').toBe(1);
        expect(findings[0].line, 'and the reported line must be the secret, not the blank').toBe(2);
      });

      // THIRD adversarial pass, MEDIUM. The first fix reused the AST path's
      // STRUCTURAL floor (`isCredibleEntropyBlob`) here. Those rules were
      // written for anonymous 40+ character runs and are far too blunt for an
      // 8-character config value: a short repeated unit and a dominant
      // character are both perfectly ordinary in a WEAK key, and a weak key is
      // still a key. These two are real secrets a scanner exists to find, and
      // both were being dropped silently.
      //
      // Asserted through the ANALYZER, not through `isVisualFiller`. A helper-
      // level assertion on this exact fix stayed green once already this
      // branch, when the consumer was reverted to a stale list and only
      // mutation caught it. The leak lives in the consumer.
      it('flags weak-but-real secrets that the structural floor dropped', () => {
        const weakButReal: Array<[string, string]> = [
          ['a repeated-unit password', 'Ab12'.repeat(6)],
          ['base64 of an all-zero AES-256 key', 'A'.repeat(43) + '='],
        ];
        for (const [label, value] of weakButReal) {
          const findings = analyzer
            .analyze([makeFile('deploy/values.yaml', `db_password: ${value}\n`)])
            .filter((f) => f.id === 'SEM-CRED-002');
          expect(findings.length, `${label} (${value}) must still be reported`).toBeGreaterThan(0);
        }
      });

      it('flags a real secret with a long filler run glued to it', () => {
        // Fourth adversarial pass, CRITICAL, asserted through the ANALYZER.
        // The value gate judged the filler SHARE of the whole value, so
        // `'_'x361 + <40-char secret>` (90.02% underscores) went silent while
        // `'_'x360 + secret` was reported — and the score ROSE by 26 points
        // because a lost true positive reads as an improvement. 360 vs 361 is
        // the giveaway that a threshold, not a property, was being measured.
        const secret = 'Zk3nQ7pR2mT9wX4vL8jH5yB0cF6dS1aG3eN7uI2o';
        for (const n of [300, 360, 361, 400, 1000]) {
          const findings = analyzer
            .analyze([makeFile('deploy/values.yaml', `db_password: ${'_'.repeat(n)}${secret}\n`)])
            .filter((f) => f.id === 'SEM-CRED-002');
          expect(findings.length, `a secret behind '_'x${n} must still be reported`).toBeGreaterThan(0);
        }
      });

      it('flags a real secret followed by a dashed trailing comment', () => {
        // The YAML value is the rest of the line, so an ordinary trailing
        // comment made the share-based rule suppress an ordinary config file.
        const findings = analyzer
          .analyze([makeFile('deploy/values.yaml', `api_key: Zq7Wn2Rt9Yb4Kd6Mf8Hj3 # ${'-'.repeat(240)}\n`)])
          .filter((f) => f.id === 'SEM-CRED-002');
        expect(findings.length, 'a trailing comment is not part of the secret').toBeGreaterThan(0);
      });

      it('rejects drawn blanks of every filler character, not just underscores', () => {
        // The rule that replaced the structural floor keys on the filler
        // CHARACTERS, so it has to cover the whole family a document draws
        // with — otherwise the reported complaint just moves one character over.
        const blanks: Array<[string, string]> = [
          ['underscores', '_'.repeat(47)],
          ['dashes', '-'.repeat(40)],
          ['dots', '.'.repeat(30)],
          ['asterisks', '*'.repeat(24)],
          ['a blank with one stray mark', '_'.repeat(46) + '1'],
          ['a redaction bar', 'x'.repeat(32)],
        ];
        for (const [label, value] of blanks) {
          const findings = analyzer
            .analyze([makeFile('deploy/values.yaml', `db_password: ${value}\n`)])
            .filter((f) => f.id === 'SEM-CRED-002');
          expect(findings, `${label} is a drawn blank, not a secret`).toHaveLength(0);
        }
      });
    });
  });

  describe('credentials in instruction files', () => {
    it('detects API key patterns in CLAUDE.md', () => {
      const file = makeFile('CLAUDE.md', 'Use this key: sk-ant-api03-abc123def456789012345678', 'agent_instructions');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-003')).toBe(true);
      expect(findings[0].severity).toBe('critical');
    });

    it('detects Bearer tokens in instruction files', () => {
      const file = makeFile('CLAUDE.md', 'Auth: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123', 'agent_instructions');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-003')).toBe(true);
    });

    it('does not flag non-instruction files', () => {
      const file = makeFile('README.md', 'Use this key: sk-ant-api03-abc123def456789012345678', 'other');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-003')).toHaveLength(0);
    });

    // A fill-in-the-blank form rule is not a credential, so the generic
    // value patterns skip a captured value that is one repeated character.
    it('does not flag a fill-in-the-blank form rule', () => {
      const file = makeFile('CLAUDE.md', `Password: ${'_'.repeat(40)}`, 'agent_instructions');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-003')).toHaveLength(0);
    });

    // Adversarial Phase 4.5: the analyzer took only the FIRST match per line,
    // so a rejected form blank earlier on the line suppressed a real token
    // beside it. It now walks every match on the line.
    it('detects a real token that shares a line with a rejected form blank', () => {
      const file = makeFile(
        'CLAUDE.md',
        `password: ${'_'.repeat(40)}  token: aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG`,
        'agent_instructions',
      );
      const findings = analyzer.analyze([file]);
      expect(
        findings.filter((f) => f.id === 'SEM-CRED-003').length,
        'a form blank earlier on the line must not mask the real token after it',
      ).toBeGreaterThan(0);
    });

    it('still detects a real token on its own line (control)', () => {
      const file = makeFile('CLAUDE.md', 'token = aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG', 'agent_instructions');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-003').length).toBeGreaterThan(0);
    });
  });

  describe('MCP env secrets', () => {
    it('does not flag a form blank in an MCP env block (SEM-CRED-004)', () => {
      // Adversarial review MEDIUM: SEM-CRED-004 had a key-name test and NO
      // value test, so the reported false positive reproduced one file type
      // over — an onboarding `.mcp.json` template scored CRITICAL on a drawn
      // blank. The shared value gate now guards this call site too.
      const file = makeFile(
        '.mcp.json',
        JSON.stringify({ mcpServers: { gh: { env: { GITHUB_TOKEN: '_'.repeat(47), API_KEY: '-'.repeat(30) } } } }, null, 2),
        'mcp_config',
      );
      const findings = analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-004');
      expect(
        findings,
        `a form blank in an MCP env block is not a secret. Got: ${findings.map((f) => f.title).join(', ')}`,
      ).toHaveLength(0);
    });

    it('STILL flags a real secret in an MCP env block (control)', () => {
      const file = makeFile(
        '.mcp.json',
        JSON.stringify({ mcpServers: { gh: { env: { GITHUB_TOKEN: 'ghp_' + 'a'.repeat(36), DB_PASSWORD: 'dev_pass' } } } }, null, 2),
        'mcp_config',
      );
      const findings = analyzer.analyze([file]).filter((f) => f.id === 'SEM-CRED-004');
      expect(findings.length, 'real secrets in an MCP env block must still fire').toBeGreaterThan(1);
    });

    it('detects hardcoded secrets in MCP server env blocks', () => {
      const content = JSON.stringify({
        mcpServers: {
          myserver: {
            command: 'node',
            args: ['server.js'],
            env: {
              API_KEY: 'sk-ant-api03-realKeyValue1234567890',
            },
          },
        },
      });
      const file = makeFile('.cursor/mcp.json', content, 'mcp_config');
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-CRED-004')).toBe(true);
      expect(findings[0].severity).toBe('critical');
    });

    it('ignores env var references in MCP env blocks', () => {
      const content = JSON.stringify({
        mcpServers: {
          myserver: {
            command: 'node',
            args: ['server.js'],
            env: {
              API_KEY: '${API_KEY}',
            },
          },
        },
      });
      const file = makeFile('.cursor/mcp.json', content, 'mcp_config');
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-CRED-004')).toHaveLength(0);
    });
  });
});
