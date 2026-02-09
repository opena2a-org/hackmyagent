import { describe, it, expect } from 'vitest';
import { CredentialContextAnalyzer } from '../structural/credential-context';
import type { AnalysisFile } from '../types';

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
  });

  describe('MCP env secrets', () => {
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
