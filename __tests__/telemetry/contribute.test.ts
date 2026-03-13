/**
 * Tests for community contribution module.
 *
 * Verifies:
 *   - Payload structure matches server-side schema exactly
 *   - No PII (file paths, line numbers, descriptions, fix text) in payload
 *   - Contributor token is stable across calls
 *   - No extra fields leak into the payload
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  generateContributorToken,
  buildContributionPayload,
  buildContributionPayloadFromDir,
  submitContribution,
  type ContributionPayload,
} from '../../src/telemetry/contribute';
import type { SecurityFinding } from '../../src/hardening';

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'contribute-test-'));
}

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Sample findings with full detail (file paths, line numbers, descriptions, fix text).
 * The contribution module must strip all of this.
 */
function makeSampleFindings(): SecurityFinding[] {
  return [
    {
      checkId: 'CRED-001',
      name: 'Hardcoded API key',
      description: 'Found hardcoded API key in src/config.ts',
      category: 'credentials',
      severity: 'critical' as const,
      passed: false,
      message: 'API key sk-1234 found in source code',
      fixable: true,
      fixed: false,
      file: 'src/config.ts',
      line: 42,
      fix: 'Remove the key and use environment variables',
      details: { keyPattern: 'sk-*', context: 'const key = "sk-1234"' },
    },
    {
      checkId: 'MCP-003',
      name: 'MCP server config',
      description: 'MCP server config is world-readable',
      category: 'mcp',
      severity: 'high' as const,
      passed: false,
      message: 'File permissions are 0644',
      fixable: true,
      fixed: false,
      file: '.mcp/config.json',
      line: 1,
      fix: 'chmod 600 .mcp/config.json',
    },
    {
      checkId: 'GIT-001',
      name: 'Gitignore coverage',
      description: '.gitignore covers secrets',
      category: 'git',
      severity: 'low' as const,
      passed: true,
      message: 'OK',
      fixable: false,
    },
    {
      checkId: 'NET-002',
      name: 'TLS configuration',
      description: 'TLS is properly configured',
      category: 'network',
      severity: 'medium' as const,
      passed: true,
      message: 'TLS 1.3 enabled',
      fixable: false,
    },
  ] as SecurityFinding[];
}

// ---------------------------------------------------------------
// generateContributorToken
// ---------------------------------------------------------------

describe('generateContributorToken', () => {
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    cleanupDir(tmpHome);
  });

  it('returns a 64-character hex string (SHA-256)', () => {
    const token = generateContributorToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is stable across calls (same device, same salt)', () => {
    const token1 = generateContributorToken();
    const token2 = generateContributorToken();
    expect(token1).toBe(token2);
  });

  it('creates contributor-salt file on first call', () => {
    generateContributorToken();
    const saltPath = path.join(tmpHome, 'contributor-salt');
    expect(fs.existsSync(saltPath)).toBe(true);
    const salt = fs.readFileSync(saltPath, 'utf-8').trim();
    expect(salt).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different tokens with different salts', () => {
    const token1 = generateContributorToken();

    // Replace the salt
    const saltPath = path.join(tmpHome, 'contributor-salt');
    fs.writeFileSync(saltPath, 'different-salt-value');

    const token2 = generateContributorToken();
    expect(token1).not.toBe(token2);
  });
});

// ---------------------------------------------------------------
// buildContributionPayload
// ---------------------------------------------------------------

describe('buildContributionPayload', () => {
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    cleanupDir(tmpHome);
  });

  it('matches the expected schema exactly', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload(
      '@test/my-agent',
      '1.0.0',
      'npm',
      findings,
    );

    // Verify all required fields exist
    expect(payload.contributorToken).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.packageName).toBe('@test/my-agent');
    expect(payload.packageVersion).toBe('1.0.0');
    expect(payload.ecosystem).toBe('npm');
    expect(payload.scanTimestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(payload.hmaVersion).toBeDefined();
    expect(['linux', 'macos', 'windows']).toContain(payload.osType);

    // Verify findings count matches input
    expect(payload.findings).toHaveLength(4);
  });

  it('strips file paths from findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);
    const json = JSON.stringify(payload);

    expect(json).not.toContain('src/config.ts');
    expect(json).not.toContain('.mcp/config.json');
    expect(json).not.toContain('file');  // no "file" key in findings
  });

  it('strips line numbers from findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    for (const f of payload.findings) {
      expect(f).not.toHaveProperty('line');
    }
  });

  it('strips descriptions from findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    for (const f of payload.findings) {
      expect(f).not.toHaveProperty('description');
      expect(f).not.toHaveProperty('message');
      expect(f).not.toHaveProperty('name');
    }
    const json = JSON.stringify(payload);
    expect(json).not.toContain('Hardcoded API key');
    expect(json).not.toContain('world-readable');
  });

  it('strips fix text from findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    for (const f of payload.findings) {
      expect(f).not.toHaveProperty('fix');
      expect(f).not.toHaveProperty('fixMessage');
    }
    const json = JSON.stringify(payload);
    expect(json).not.toContain('Remove the key');
    expect(json).not.toContain('chmod');
  });

  it('strips details/extras from findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    for (const f of payload.findings) {
      expect(f).not.toHaveProperty('details');
      expect(f).not.toHaveProperty('category');
    }
    const json = JSON.stringify(payload);
    expect(json).not.toContain('sk-1234');
    expect(json).not.toContain('keyPattern');
  });

  it('has no extra fields in findings (privacy enforcement)', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    const allowedFindingKeys = new Set(['checkId', 'result', 'severity']);
    for (const f of payload.findings) {
      const keys = Object.keys(f);
      for (const key of keys) {
        expect(allowedFindingKeys.has(key)).toBe(true);
      }
      expect(keys).toHaveLength(3);
    }
  });

  it('has no extra fields in the top-level payload', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    const allowedKeys = new Set([
      'contributorToken',
      'packageName',
      'packageVersion',
      'ecosystem',
      'scanTimestamp',
      'findings',
      'hmaVersion',
      'osType',
    ]);

    const keys = Object.keys(payload);
    for (const key of keys) {
      expect(allowedKeys.has(key)).toBe(true);
    }
    expect(keys).toHaveLength(8);
  });

  it('maps passed findings to result "pass"', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    const gitFinding = payload.findings.find((f) => f.checkId === 'GIT-001');
    expect(gitFinding?.result).toBe('pass');
  });

  it('maps failed findings to result "fail"', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    const credFinding = payload.findings.find((f) => f.checkId === 'CRED-001');
    expect(credFinding?.result).toBe('fail');
  });

  it('preserves severity from original findings', () => {
    const findings = makeSampleFindings();
    const payload = buildContributionPayload('test', '1.0', 'npm', findings);

    const credFinding = payload.findings.find((f) => f.checkId === 'CRED-001');
    expect(credFinding?.severity).toBe('critical');

    const mcpFinding = payload.findings.find((f) => f.checkId === 'MCP-003');
    expect(mcpFinding?.severity).toBe('high');
  });

  it('accepts all valid ecosystem values', () => {
    const findings: SecurityFinding[] = [];
    for (const eco of ['npm', 'pypi', 'github'] as const) {
      const payload = buildContributionPayload('test', '1.0', eco, findings);
      expect(payload.ecosystem).toBe(eco);
    }
  });

  it('handles empty findings array', () => {
    const payload = buildContributionPayload('test', '1.0', 'npm', []);
    expect(payload.findings).toHaveLength(0);
  });

  it('handles empty package version', () => {
    const payload = buildContributionPayload('test', '', 'npm', []);
    expect(payload.packageVersion).toBe('');
  });
});

// ---------------------------------------------------------------
// buildContributionPayloadFromDir
// ---------------------------------------------------------------

describe('buildContributionPayloadFromDir', () => {
  let tmpHome: string;
  let tmpDir: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    tmpDir = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    cleanupDir(tmpHome);
    cleanupDir(tmpDir);
  });

  it('detects npm ecosystem from package.json', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'test', version: '2.0.0' }),
    );

    const payload = buildContributionPayloadFromDir('test', tmpDir, []);
    expect(payload.ecosystem).toBe('npm');
    expect(payload.packageVersion).toBe('2.0.0');
  });

  it('detects pypi ecosystem from setup.py', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'setup.py'),
      'setup(name="test", version="3.1.0")',
    );

    const payload = buildContributionPayloadFromDir('test', tmpDir, []);
    expect(payload.ecosystem).toBe('pypi');
    expect(payload.packageVersion).toBe('3.1.0');
  });

  it('falls back to github ecosystem', () => {
    const payload = buildContributionPayloadFromDir('test', tmpDir, []);
    expect(payload.ecosystem).toBe('github');
  });
});

// ---------------------------------------------------------------
// submitContribution (with mocked fetch)
// ---------------------------------------------------------------

describe('submitContribution', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('submits payload and returns success with scanId', async () => {
    const response = {
      ok: true,
      json: async () => ({ scanId: 'scan-123' }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    const payload: ContributionPayload = {
      contributorToken: 'abc123',
      packageName: 'test',
      packageVersion: '1.0.0',
      ecosystem: 'npm',
      scanTimestamp: new Date().toISOString(),
      findings: [],
      hmaVersion: '0.10.0',
      osType: 'macos',
    };

    const result = await submitContribution(payload, 'https://registry.opena2a.org');

    expect(result.success).toBe(true);
    expect(result.scanId).toBe('scan-123');

    // Verify the correct endpoint was called
    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://registry.opena2a.org/api/v1/telemetry/scan');
    expect(fetchCall[1].method).toBe('POST');
  });

  it('handles HTTP errors gracefully', async () => {
    const response = {
      ok: false,
      status: 422,
      text: async () => 'Validation failed',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    const payload: ContributionPayload = {
      contributorToken: 'abc',
      packageName: 'test',
      packageVersion: '1.0.0',
      ecosystem: 'npm',
      scanTimestamp: new Date().toISOString(),
      findings: [],
      hmaVersion: '0.10.0',
      osType: 'linux',
    };

    const result = await submitContribution(payload);
    expect(result.success).toBe(false);
    expect(result.error).toContain('422');
  });

  it('handles network errors gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')));

    const payload: ContributionPayload = {
      contributorToken: 'abc',
      packageName: 'test',
      packageVersion: '1.0.0',
      ecosystem: 'npm',
      scanTimestamp: new Date().toISOString(),
      findings: [],
      hmaVersion: '0.10.0',
      osType: 'windows',
    };

    const result = await submitContribution(payload);
    expect(result.success).toBe(false);
    expect(result.error).toContain('ECONNREFUSED');
  });

  it('uses default registry URL when none provided', async () => {
    const response = {
      ok: true,
      json: async () => ({ scanId: 'scan-default' }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    const payload: ContributionPayload = {
      contributorToken: 'abc',
      packageName: 'test',
      packageVersion: '1.0.0',
      ecosystem: 'npm',
      scanTimestamp: new Date().toISOString(),
      findings: [],
      hmaVersion: '0.10.0',
      osType: 'macos',
    };

    await submitContribution(payload);

    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://registry.opena2a.org/api/v1/telemetry/scan');
  });
});
