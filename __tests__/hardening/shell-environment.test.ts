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

import { checkShellEnvironment } from '../../src/hardening/shell-checks';

describe('checkShellEnvironment', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
    vi.mocked(os.homedir).mockReturnValue(tempDir);
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('SHELL-001: detects Anthropic key in .bashrc', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      'export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings.find((f) => f.checkId === 'SHELL-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.passed).toBe(false);
    expect(finding?.fixable).toBe(false);
    expect(finding?.file).toBe('~/.bashrc');
    expect(finding?.category).toBe('credential-exposure');
    expect(finding?.fix).toContain('secretless-ai doctor');
  });

  it('SHELL-002: detects OpenAI key in .zshrc', async () => {
    await fs.writeFile(
      path.join(tempDir, '.zshrc'),
      'export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234\n'
    );

    const findings = await checkShellEnvironment();

    const finding = findings.find((f) => f.checkId === 'SHELL-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.passed).toBe(false);
    expect(finding?.file).toBe('~/.zshrc');
    expect(finding?.message).toContain('.zshrc');
    expect(finding?.message).toContain('OPENAI_API_KEY');
  });

  it('SHELL-003: detects AWS key in .profile', async () => {
    await fs.writeFile(
      path.join(tempDir, '.profile'),
      'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
    );

    const findings = await checkShellEnvironment();

    const finding = findings.find((f) => f.checkId === 'SHELL-003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.passed).toBe(false);
    expect(finding?.file).toBe('~/.profile');
  });

  it('SHELL-004: detects GitHub token in .zshenv', async () => {
    await fs.writeFile(
      path.join(tempDir, '.zshenv'),
      'export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellEnvironment();

    const finding = findings.find((f) => f.checkId === 'SHELL-004');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.passed).toBe(false);
    expect(finding?.file).toBe('~/.zshenv');
  });

  it('skips comment lines', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      '# export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings).toHaveLength(0);
  });

  it('skips indented comment lines', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      '  # export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings).toHaveLength(0);
  });

  it('skips env var references with ${VAR} syntax', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      'export ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings).toHaveLength(0);
  });

  it('skips env var references with $VAR syntax', async () => {
    await fs.writeFile(
      path.join(tempDir, '.zshrc'),
      'export OPENAI_API_KEY=$OPENAI_API_KEY\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings).toHaveLength(0);
  });

  it('skips non-existent files gracefully', async () => {
    // No shell config files created in tempDir
    const findings = await checkShellEnvironment();

    expect(findings).toHaveLength(0);
  });

  it('reports correct file path with ~/ notation', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      'export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].file).toBe('~/.bashrc');
    expect(findings[0].line).toBe(1);
  });

  it('reports correct line number for multi-line files', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      [
        '# Safe comment',
        'export PATH=/usr/local/bin:$PATH',
        '',
        'export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890',
      ].join('\n')
    );

    const findings = await checkShellEnvironment();

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].line).toBe(4);
  });

  it('detects multiple credentials across multiple files', async () => {
    await fs.writeFile(
      path.join(tempDir, '.bashrc'),
      'export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\n'
    );
    await fs.writeFile(
      path.join(tempDir, '.zshrc'),
      'export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234\n'
    );

    const findings = await checkShellEnvironment();

    expect(findings.length).toBeGreaterThanOrEqual(2);
    const checkIds = findings.map((f) => f.checkId);
    expect(checkIds).toContain('SHELL-001');
    expect(checkIds).toContain('SHELL-002');
  });
});
