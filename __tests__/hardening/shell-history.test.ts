import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

// Mock os.homedir() before importing the module under test
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os');
  return {
    ...actual,
    homedir: vi.fn(() => '/tmp/mock-home'),
  };
});

import { checkShellHistory } from '../../src/hardening/shell-checks';

describe('checkShellHistory', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
    vi.mocked(os.homedir).mockReturnValue(tempDir);
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('SHELLHIST-001: detects pasted API key in .bash_history', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'ls -la\nsk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\ncd /tmp\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.passed).toBe(false);
    expect(finding?.fixable).toBe(false);
    expect(finding?.file).toBe('~/.bash_history');
    expect(finding?.category).toBe('credential-exposure');
  });

  it('SHELLHIST-001: detects OpenAI key in .bash_history', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'echo sk-proj-abcdefghijklmnopqrstuvwxyz1234\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('OPENAI_API_KEY');
  });

  it('SHELLHIST-002: detects pasted key in .zsh_history with timestamp prefix stripped', async () => {
    await fs.writeFile(
      path.join(tempDir, '.zsh_history'),
      ': 1234567890:0;export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.file).toBe('~/.zsh_history');
  });

  it('SHELLHIST-002: detects AWS key in history', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('AWS_ACCESS_KEY');
  });

  it('SHELLHIST-003: detects credential in curl command', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'curl -H "Authorization: Bearer sk-some-really-long-token-value-here-1234567890" https://api.example.com\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.passed).toBe(false);
    expect(finding?.fixable).toBe(false);
    expect(finding?.name).toBe('Credential in command arguments');
  });

  it('detects --api-key flag with value', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'mytool --api-key=sk-some-really-long-secret-key-value-1234567890 run\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.fix).toContain('environment variables');
  });

  it('detects --token flag with value', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'gh auth login --token=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellHistory();

    // This should match either SHELLHIST-001/002 (credential pattern) or SHELLHIST-003 (command pattern)
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects export VAR=secret patterns in history', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-001');
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('ANTHROPIC_API_KEY');
  });

  it('strips zsh timestamp prefix format correctly', async () => {
    await fs.writeFile(
      path.join(tempDir, '.zsh_history'),
      [
        ': 1709000000:0;ls -la',
        ': 1709000001:0;sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890',
        ': 1709000002:0;cd ~',
      ].join('\n')
    );

    const findings = await checkShellHistory();

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings.find((f) => f.checkId === 'SHELLHIST-001');
    expect(finding).toBeDefined();
    expect(finding?.file).toBe('~/.zsh_history');
  });

  it('only reads last 10,000 lines', async () => {
    // Create a history file with more than 10,000 lines
    // Put a credential at line 5 (should be outside the scanned window)
    const lines: string[] = [];
    lines.push('sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890'); // line 1
    for (let i = 0; i < 10_005; i++) {
      lines.push(`command-${i}`);
    }

    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      lines.join('\n')
    );

    const findings = await checkShellHistory();

    // The credential at line 1 should be excluded because only last 10K lines are scanned
    // and the file has 10,006 lines total, so line 1 is before the window
    const anthropicFinding = findings.find(
      (f) => f.message?.includes('ANTHROPIC_API_KEY')
    );
    expect(anthropicFinding).toBeUndefined();
  });

  it('skips non-existent history files gracefully', async () => {
    // No history files created in tempDir
    const findings = await checkShellHistory();

    expect(findings).toHaveLength(0);
  });

  it('reports severity as high', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellHistory();

    for (const finding of findings) {
      expect(finding.severity).toBe('high');
    }
  });

  it('reports fixable as false', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellHistory();

    for (const finding of findings) {
      expect(finding.fixable).toBe(false);
    }
  });

  it('detects credentials in both history files', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );
    await fs.writeFile(
      path.join(tempDir, '.zsh_history'),
      ': 1709000000:0;AKIAIOSFODNN7EXAMPLE\n'
    );

    const findings = await checkShellHistory();

    expect(findings.length).toBeGreaterThanOrEqual(2);
    const files = findings.map((f) => f.file);
    expect(files).toContain('~/.bash_history');
    expect(files).toContain('~/.zsh_history');
  });

  it('detects x-api-key header in curl command', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bash_history'),
      'curl -H "x-api-key: sk-some-really-long-api-key-1234567890" https://api.anthropic.com/v1/messages\n'
    );

    const findings = await checkShellHistory();

    const finding = findings.find((f) => f.checkId === 'SHELLHIST-003');
    expect(finding).toBeDefined();
    expect(finding?.description).toContain('command argument');
  });
});
