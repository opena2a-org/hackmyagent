/**
 * Tests for ATP Publish flow (--publish flag)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  readAgentKeypair,
  signPayload,
  buildPublishPayload,
  publishScanResults,
  formatPublishOutput,
  type PublishScanData,
  type PublishResult,
} from './publish';
import type { SecurityFinding } from '../hardening';
import type { AttackReport } from '../attack';
import type { SoulScanResult } from '../soul';
import type { BenchmarkResult } from '../benchmarks';

// Helper: create a temporary directory
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'publish-test-'));
}

// Helper: clean up temporary directory
function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// Helper: create fake keypair in a temp opena2a home
function createFakeKeypair(opena2aHome: string): void {
  const keysDir = path.join(opena2aHome, 'keys');
  fs.mkdirSync(keysDir, { recursive: true });
  const crypto = require('crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(path.join(keysDir, 'agent.pub'), publicKey);
  fs.writeFileSync(path.join(keysDir, 'agent.key'), privateKey);
  fs.writeFileSync(path.join(keysDir, 'agent-id'), 'test-agent-123');
}

// Minimal fixtures
function makeHardeningFindings(): SecurityFinding[] {
  return [
    {
      checkId: 'CRED-001',
      name: 'API key in code',
      description: 'Found hardcoded API key',
      severity: 'critical' as const,
      category: 'credentials',
      passed: false,
      fixed: false,
      fix: 'Remove the key',
    },
    {
      checkId: 'GIT-001',
      name: 'Git ignoring secrets',
      description: '.gitignore covers secrets',
      severity: 'low' as const,
      category: 'git',
      passed: true,
      fixed: false,
    },
    {
      checkId: 'MCP-002',
      name: 'MCP config exposed',
      description: 'MCP config readable',
      severity: 'medium' as const,
      category: 'mcp',
      passed: false,
      fixed: false,
      fix: 'Restrict permissions',
    },
  ] as SecurityFinding[];
}

function makeAttackReport(): AttackReport {
  return {
    target: 'https://example.com/api',
    targetType: 'api',
    intensity: 'active',
    categories: ['prompt-injection'],
    startTime: new Date(),
    endTime: new Date(),
    duration: 5000,
    summary: {
      total: 10,
      successful: 2,
      blocked: 7,
      inconclusive: 1,
      bySeverity: { critical: 1, high: 1, medium: 0, low: 0 } as any,
      byCategory: { 'prompt-injection': { total: 10, successful: 2 } } as any,
    },
    results: [
      {
        payload: {
          id: 'PI-001',
          name: 'Basic injection',
          category: 'prompt-injection',
          severity: 'high',
          intensity: 'active',
          prompt: 'ignore previous instructions',
          remediation: 'Add input sanitization',
        },
        success: true,
        blocked: false,
        evidence: 'Model responded to injected prompt',
      },
      {
        payload: {
          id: 'PI-002',
          name: 'Advanced injection',
          category: 'prompt-injection',
          severity: 'critical',
          intensity: 'active',
          prompt: 'system override',
          remediation: 'Use system prompt isolation',
        },
        success: true,
        blocked: false,
        evidence: 'Model broke out of system prompt',
      },
    ],
    riskScore: 65,
    riskRating: 'high',
  } as AttackReport;
}

function makeSoulResult(): SoulScanResult {
  return {
    file: 'SOUL.md',
    fileSize: 1200,
    agentTier: 'AGENTIC',
    tierForced: false,
    agentProfile: 'tool-agent',
    profileForced: false,
    skippedDomains: [],
    domains: [],
    score: 72,
    grade: 'B' as any,
    level: 'Standard' as any,
    conformance: 'standard',
    criticalFloor: false,
    criticalMissing: [],
    totalControls: 72,
    totalPassed: 52,
  } as SoulScanResult;
}

function makeOasbResult(): BenchmarkResult {
  return {
    benchmark: 'OASB-1',
    version: '1.0',
    level: 'L1',
    timestamp: new Date(),
    compliance: 85,
    l1Compliance: 90,
    l2Compliance: 78,
    l3Compliance: 65,
    rating: 'Compliant',
    categories: [],
    totalControls: 46,
    passedControls: 39,
    failedControls: 5,
    unverifiedControls: 2,
  } as BenchmarkResult;
}

// ---------------------------------------------------------------
// readAgentKeypair
// ---------------------------------------------------------------

describe('readAgentKeypair', () => {
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

  it('returns null when keys directory does not exist', () => {
    const result = readAgentKeypair();
    expect(result).toBeNull();
  });

  it('returns null when keys directory exists but files are missing', () => {
    fs.mkdirSync(path.join(tmpHome, 'keys'), { recursive: true });
    const result = readAgentKeypair();
    expect(result).toBeNull();
  });

  it('returns keypair when both key files exist', () => {
    createFakeKeypair(tmpHome);
    const result = readAgentKeypair();
    expect(result).not.toBeNull();
    expect(result!.publicKey).toContain('PUBLIC KEY');
    expect(result!.privateKey).toContain('PRIVATE KEY');
    expect(result!.agentId).toBe('test-agent-123');
  });

  it('returns keypair without agentId when agent-id file is missing', () => {
    createFakeKeypair(tmpHome);
    fs.unlinkSync(path.join(tmpHome, 'keys', 'agent-id'));
    const result = readAgentKeypair();
    expect(result).not.toBeNull();
    expect(result!.agentId).toBeUndefined();
  });
});

// ---------------------------------------------------------------
// signPayload
// ---------------------------------------------------------------

describe('signPayload', () => {
  let tmpDir: string;
  let privateKey: string;

  beforeEach(() => {
    tmpDir = createTempDir();
    createFakeKeypair(tmpDir);
    privateKey = fs.readFileSync(path.join(tmpDir, 'keys', 'agent.key'), 'utf-8');
  });

  afterEach(() => {
    cleanupDir(tmpDir);
  });

  it('signs a payload and returns base64 signature', () => {
    const signature = signPayload('test payload', privateKey);
    expect(signature).not.toBeNull();
    expect(typeof signature).toBe('string');
    expect(signature!.length).toBeGreaterThan(10);
  });

  it('returns null for invalid private key', () => {
    const signature = signPayload('test payload', 'invalid-key');
    expect(signature).toBeNull();
  });
});

// ---------------------------------------------------------------
// buildPublishPayload
// ---------------------------------------------------------------

describe('buildPublishPayload', () => {
  it('builds payload from hardening findings', () => {
    const data: PublishScanData = {
      packageName: '@test/my-agent',
      packageVersion: '1.0.0',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
    };

    const payload = buildPublishPayload(data);

    expect(payload.packageName).toBe('@test/my-agent');
    expect(payload.version).toBe('1.0.0');
    expect(payload.scanId).toMatch(/^hma-publish-/);
    expect(payload.status).toBe('failed'); // has a critical finding
    expect(payload.criticalCount).toBe(1);
    expect(payload.mediumCount).toBe(1);
    expect(payload.vulnerabilities).toHaveLength(2); // 2 failed (critical + medium)
    expect(payload.contentHash).toBeDefined();
    expect(typeof payload.contentHash).toBe('string');
  });

  it('builds payload from attack report', () => {
    const data: PublishScanData = {
      packageName: 'my-target',
      directory: '/tmp/test',
      attackReport: makeAttackReport(),
    };

    const payload = buildPublishPayload(data);

    expect(payload.status).toBe('failed');
    expect(payload.criticalCount).toBe(1);
    expect(payload.highCount).toBe(1);
    expect(payload.attackRiskScore).toBe(65);
    expect(payload.attackRiskRating).toBe('high');
    expect(payload.attackTotal).toBe(10);
    expect(payload.attackSucceeded).toBe(2);
  });

  it('builds payload from SOUL scan result', () => {
    const data: PublishScanData = {
      packageName: '@test/agent',
      directory: '/tmp/test',
      soulResult: makeSoulResult(),
    };

    const payload = buildPublishPayload(data);

    expect(payload.status).toBe('passed');
    expect(payload.soulScore).toBe(72);
    expect(payload.soulConformance).toBe('standard');
    expect(payload.soulAgentTier).toBe('AGENTIC');
  });

  it('builds payload from OASB benchmark result', () => {
    const data: PublishScanData = {
      packageName: '@test/agent',
      directory: '/tmp/test',
      oasbResult: makeOasbResult(),
    };

    const payload = buildPublishPayload(data);

    expect(payload.oasbCompliance).toBe(85);
    expect(payload.oasbRating).toBe('Compliant');
    expect(payload.oasbL1).toBe(90);
    expect(payload.oasbL2).toBe(78);
    expect(payload.oasbL3).toBe(65);
  });

  it('combines all scan types into a unified payload', () => {
    const data: PublishScanData = {
      packageName: '@test/full-scan',
      packageVersion: '2.0.0',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
      attackReport: makeAttackReport(),
      soulResult: makeSoulResult(),
      oasbResult: makeOasbResult(),
    };

    const payload = buildPublishPayload(data);

    expect(payload.vulnerabilities.length).toBeGreaterThan(0);
    expect(payload.oasbCompliance).toBe(85);
    expect(payload.soulScore).toBe(72);
    expect(payload.attackRiskScore).toBe(65);

    const raw = payload.rawReport as Record<string, unknown>;
    expect(raw.hardening).toBeDefined();
    expect(raw.attack).toBeDefined();
    expect(raw.soul).toBeDefined();
    expect(raw.oasb).toBeDefined();
    expect(raw.publishedVia).toBe('atp-publish');
  });

  it('sets status to passed when no failed findings exist', () => {
    const passingFindings: SecurityFinding[] = [
      {
        checkId: 'GIT-001',
        name: 'Git config',
        description: 'OK',
        severity: 'low' as const,
        category: 'git',
        passed: true,
        fixed: false,
      },
    ] as SecurityFinding[];

    const data: PublishScanData = {
      packageName: '@test/clean',
      directory: '/tmp/test',
      hardeningFindings: passingFindings,
    };

    const payload = buildPublishPayload(data);
    expect(payload.status).toBe('passed');
    expect(payload.criticalCount).toBe(0);
    expect(payload.highCount).toBe(0);
  });

  it('sets status to warnings when only medium/low findings', () => {
    const findings: SecurityFinding[] = [
      {
        checkId: 'LOG-001',
        name: 'Verbose logging',
        description: 'Logging too verbose',
        severity: 'low' as const,
        category: 'logging',
        passed: false,
        fixed: false,
      },
    ] as SecurityFinding[];

    const data: PublishScanData = {
      packageName: '@test/warn',
      directory: '/tmp/test',
      hardeningFindings: findings,
    };

    const payload = buildPublishPayload(data);
    expect(payload.status).toBe('warnings');
  });
});

// ---------------------------------------------------------------
// publishScanResults (with mocked fetch)
// ---------------------------------------------------------------

describe('publishScanResults', () => {
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
    vi.unstubAllGlobals();
    cleanupDir(tmpHome);
  });

  it('publishes as community scan when no keypair exists', async () => {
    const mockResponse = {
      ok: true,
      json: async () => ({ scanId: 'scan-abc', profileUrl: 'https://registry.opena2a.org/agents/test', status: 'accepted' }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse));

    const data: PublishScanData = {
      packageName: '@test/agent',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
    };

    const result = await publishScanResults(data, 'https://registry.opena2a.org');

    expect(result.success).toBe(true);
    expect(result.isCommunity).toBe(true);
    expect(result.scanId).toBe('scan-abc');
    expect(result.status).toBe('accepted');
  });

  it('publishes as claimed agent when keypair exists', async () => {
    createFakeKeypair(tmpHome);

    const mockResponse = {
      ok: true,
      json: async () => ({ scanId: 'scan-xyz', profileUrl: 'https://registry.opena2a.org/agents/claimed', status: 'accepted' }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse));

    const data: PublishScanData = {
      packageName: '@test/claimed-agent',
      directory: '/tmp/test',
      soulResult: makeSoulResult(),
    };

    const result = await publishScanResults(data, 'https://registry.opena2a.org');

    expect(result.success).toBe(true);
    expect(result.isCommunity).toBe(false);

    // Check that signature and publicKey were sent
    const fetchCalls = (fetch as any).mock.calls;
    expect(fetchCalls.length).toBe(1);
    const body = JSON.parse(fetchCalls[0][1].body);
    expect(body.signature).toBeDefined();
    expect(body.publicKey).toBeDefined();
    expect(body.agentId).toBe('test-agent-123');
  });

  it('handles registry errors gracefully', async () => {
    const mockResponse = {
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse));

    const data: PublishScanData = {
      packageName: '@test/agent',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
    };

    const result = await publishScanResults(data, 'https://registry.opena2a.org');

    expect(result.success).toBe(false);
    expect(result.error).toContain('500');
    expect(result.isCommunity).toBe(true);
  });

  it('handles network errors gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

    const data: PublishScanData = {
      packageName: '@test/agent',
      directory: '/tmp/test',
      hardeningFindings: [],
    };

    const result = await publishScanResults(data, 'https://registry.opena2a.org');

    expect(result.success).toBe(false);
    expect(result.error).toContain('ECONNREFUSED');
  });
});

// ---------------------------------------------------------------
// formatPublishOutput
// ---------------------------------------------------------------

describe('formatPublishOutput', () => {
  it('formats successful claimed publish', () => {
    const result: PublishResult = {
      success: true,
      scanId: 'scan-abc',
      profileUrl: 'https://registry.opena2a.org/agents/123',
      status: 'passed (3 warnings)',
      isCommunity: false,
    };

    const data: PublishScanData = {
      packageName: '@anthropic/mcp-server-fetch',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
    };

    const output = formatPublishOutput(result, data, 'https://registry.opena2a.org');

    expect(output).toContain('Published to registry.opena2a.org');
    expect(output).toContain('@anthropic/mcp-server-fetch');
    expect(output).toContain('scan-abc');
    expect(output).toContain('Trust impact');
    expect(output).toContain('https://registry.opena2a.org/agents/123');
    expect(output).not.toContain('community scan');
  });

  it('formats successful community publish with fallback notice', () => {
    const result: PublishResult = {
      success: true,
      scanId: 'scan-def',
      profileUrl: 'https://registry.opena2a.org/agents/456',
      status: 'passed',
      isCommunity: true,
    };

    const data: PublishScanData = {
      packageName: 'my-agent',
      directory: '/tmp/test',
      soulResult: makeSoulResult(),
    };

    const output = formatPublishOutput(result, data, 'https://registry.opena2a.org');

    expect(output).toContain('Published to registry.opena2a.org');
    expect(output).toContain('community scan (0.5x weight)');
    expect(output).toContain('opena2a claim');
  });

  it('formats failed publish', () => {
    const result: PublishResult = {
      success: false,
      scanId: 'scan-fail',
      profileUrl: '',
      status: 'error',
      isCommunity: true,
      error: 'Connection refused',
    };

    const data: PublishScanData = {
      packageName: 'my-agent',
      directory: '/tmp/test',
    };

    const output = formatPublishOutput(result, data, 'https://registry.opena2a.org');

    expect(output).toContain('Failed to publish');
    expect(output).toContain('Connection refused');
    expect(output).toContain('available locally');
  });

  it('includes scan type summary in output', () => {
    const result: PublishResult = {
      success: true,
      scanId: 'scan-all',
      profileUrl: 'https://registry.opena2a.org/agents/789',
      status: 'passed',
      isCommunity: false,
    };

    const data: PublishScanData = {
      packageName: '@test/all-scans',
      directory: '/tmp/test',
      hardeningFindings: makeHardeningFindings(),
      attackReport: makeAttackReport(),
      soulResult: makeSoulResult(),
      oasbResult: makeOasbResult(),
    };

    const output = formatPublishOutput(result, data, 'https://registry.opena2a.org');

    expect(output).toContain('hardening');
    expect(output).toContain('OASB');
    expect(output).toContain('SOUL');
    expect(output).toContain('attack');
  });
});
