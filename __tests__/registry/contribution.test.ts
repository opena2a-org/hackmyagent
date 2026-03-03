/**
 * Anonymous Registry Contribution Tests
 *
 * Validates that contribution payloads are correctly built from scan results
 * and that ZERO personally identifiable information leaks into submissions.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  hashArtifact,
  generateContributionId,
  extractFindingIds,
  countBySeverity,
  buildHardeningContribution,
  buildGovernanceContribution,
  buildMcpContribution,
  buildAttackContribution,
  submitContribution,
  ContributionPayload,
} from '../../src/registry/contribution';

// ---------------------------------------------------------------------------
// hashArtifact
// ---------------------------------------------------------------------------
describe('hashArtifact', () => {
  it('returns consistent SHA256 for same content', () => {
    const content = 'agent-config-file-content-here';
    const hash1 = hashArtifact(content);
    const hash2 = hashArtifact(content);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('returns different hashes for different content', () => {
    const hash1 = hashArtifact('content-alpha');
    const hash2 = hashArtifact('content-beta');
    expect(hash1).not.toBe(hash2);
  });
});

// ---------------------------------------------------------------------------
// generateContributionId
// ---------------------------------------------------------------------------
describe('generateContributionId', () => {
  it('returns valid UUID format', () => {
    const id = generateContributionId();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('returns unique values on successive calls', () => {
    const ids = new Set(Array.from({ length: 50 }, () => generateContributionId()));
    expect(ids.size).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// extractFindingIds
// ---------------------------------------------------------------------------
describe('extractFindingIds', () => {
  it('deduplicates IDs', () => {
    const findings = [
      { checkId: 'SHELL-001' },
      { checkId: 'SHELL-001' },
      { checkId: 'CRED-003' },
    ];
    const ids = extractFindingIds(findings);
    expect(ids).toEqual(['CRED-003', 'SHELL-001']);
  });

  it('sorts alphabetically', () => {
    const findings = [
      { checkId: 'ZZZ-001' },
      { checkId: 'AAA-001' },
      { checkId: 'MMM-001' },
    ];
    const ids = extractFindingIds(findings);
    expect(ids).toEqual(['AAA-001', 'MMM-001', 'ZZZ-001']);
  });

  it('returns empty array for empty input', () => {
    expect(extractFindingIds([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// countBySeverity
// ---------------------------------------------------------------------------
describe('countBySeverity', () => {
  it('counts only failed findings', () => {
    const findings = [
      { severity: 'critical', passed: false },
      { severity: 'critical', passed: true },
      { severity: 'high', passed: false },
      { severity: 'medium', passed: false },
      { severity: 'medium', passed: true },
      { severity: 'low', passed: false },
    ];
    const counts = countBySeverity(findings);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(1);
  });

  it('handles empty array', () => {
    const counts = countBySeverity([]);
    expect(counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
  });

  it('ignores findings without passed field', () => {
    const findings = [
      { severity: 'critical' },
      { severity: 'high' },
    ];
    const counts = countBySeverity(findings);
    expect(counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
  });
});

// ---------------------------------------------------------------------------
// buildHardeningContribution
// ---------------------------------------------------------------------------
describe('buildHardeningContribution', () => {
  const findings = [
    { checkId: 'SHELL-001', severity: 'critical', passed: false },
    { checkId: 'CRED-003', severity: 'high', passed: false },
    { checkId: 'NET-002', severity: 'medium', passed: true },
    { checkId: 'FS-001', severity: 'low', passed: false },
  ];

  it('populates all required fields', () => {
    const payload = buildHardeningContribution('0.8.0', 'config-content', findings, 72, 100, 450);
    expect(payload.contributionId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(payload.artifactHash).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.scanType).toBe('hardening');
    expect(payload.scannerVersion).toBe('0.8.0');
    expect(payload.scanTimestamp).toBeTruthy();
    expect(payload.scanDurationMs).toBe(450);
    expect(payload.score).toBe(72);
    expect(payload.maxScore).toBe(100);
  });

  it('includes only failed finding IDs', () => {
    const payload = buildHardeningContribution('0.8.0', 'config-content', findings, 72, 100);
    expect(payload.findingIds).toContain('SHELL-001');
    expect(payload.findingIds).toContain('CRED-003');
    expect(payload.findingIds).toContain('FS-001');
    expect(payload.findingIds).not.toContain('NET-002');
  });

  it('does not include file paths', () => {
    const payload = buildHardeningContribution('0.8.0', '/home/user/project/.cursor/mcp.json', findings, 72, 100);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('/home/user');
    expect(serialized).not.toContain('.cursor');
    expect(serialized).not.toContain('mcp.json');
  });

  it('does not include descriptions', () => {
    const findingsWithDesc = [
      { checkId: 'SHELL-001', severity: 'critical', passed: false, description: 'Shell access vulnerability in /usr/bin' },
    ];
    const payload = buildHardeningContribution('0.8.0', 'content', findingsWithDesc, 50, 100);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('Shell access vulnerability');
    expect(serialized).not.toContain('/usr/bin');
  });

  it('counts severity correctly', () => {
    const payload = buildHardeningContribution('0.8.0', 'content', findings, 72, 100);
    expect(payload.criticalCount).toBe(1);
    expect(payload.highCount).toBe(1);
    expect(payload.mediumCount).toBe(0); // NET-002 passed, not counted
    expect(payload.lowCount).toBe(1);
    expect(payload.totalFindings).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// buildGovernanceContribution
// ---------------------------------------------------------------------------
describe('buildGovernanceContribution', () => {
  const governanceScore = {
    overall: 65,
    grade: 'C',
    tier: 'Tier 2',
    domains: [
      { domain: 'transparency', score: 80, controlsPassed: 4, controlsTotal: 5 },
      { domain: 'safety', score: 50, controlsPassed: 2, controlsTotal: 4 },
    ],
    results: [
      { controlId: 'GOV-001', severity: 'critical', passed: false },
      { controlId: 'GOV-002', severity: 'high', passed: true },
      { controlId: 'GOV-003', severity: 'medium', passed: false },
    ],
    criticalFailures: ['GOV-001'],
  };

  it('includes domain scores', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore);
    expect(payload.governance).toBeDefined();
    expect(payload.governance!.domainScores).toHaveLength(2);
    expect(payload.governance!.domainScores[0].domain).toBe('transparency');
    expect(payload.governance!.domainScores[0].score).toBe(80);
    expect(payload.governance!.domainScores[1].domain).toBe('safety');
    expect(payload.governance!.domainScores[1].controlsPassed).toBe(2);
    expect(payload.governance!.domainScores[1].controlsTotal).toBe(4);
  });

  it('includes critical failures as control IDs only', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore);
    expect(payload.governance!.criticalFailures).toEqual(['GOV-001']);
  });

  it('includes tier', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore);
    expect(payload.governance!.tier).toBe('Tier 2');
  });

  it('sets score, maxScore, and grade', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore);
    expect(payload.score).toBe(65);
    expect(payload.maxScore).toBe(100);
    expect(payload.grade).toBe('C');
  });

  it('counts only failed results', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore);
    expect(payload.totalFindings).toBe(2);
    expect(payload.criticalCount).toBe(1);
    expect(payload.mediumCount).toBe(1);
    expect(payload.highCount).toBe(0);
  });

  it('includes scanDurationMs when provided', () => {
    const payload = buildGovernanceContribution('0.8.0', 'soul-content', governanceScore, 1200);
    expect(payload.scanDurationMs).toBe(1200);
  });
});

// ---------------------------------------------------------------------------
// buildMcpContribution
// ---------------------------------------------------------------------------
describe('buildMcpContribution', () => {
  const serverResults = [
    {
      serverName: 'server-a',
      toolCount: 5,
      findings: [
        { checkId: 'MCPTOOL-001', severity: 'critical' },
        { checkId: 'MCPTOOL-002', severity: 'high' },
      ],
    },
    {
      serverName: 'server-b',
      toolCount: 3,
      findings: [
        { checkId: 'MCPTOOL-003', severity: 'medium' },
      ],
    },
  ];

  it('includes server count', () => {
    const payload = buildMcpContribution('0.8.0', 'mcp-config', serverResults);
    expect(payload.mcpEnumeration).toBeDefined();
    expect(payload.mcpEnumeration!.serversScanned).toBe(2);
  });

  it('includes tool categories', () => {
    const payload = buildMcpContribution('0.8.0', 'mcp-config', serverResults);
    expect(payload.mcpEnumeration!.categories).toContain('execution');
    expect(payload.mcpEnumeration!.categories).toContain('filesystem');
    expect(payload.mcpEnumeration!.categories).toContain('network');
  });

  it('sums total tools across servers', () => {
    const payload = buildMcpContribution('0.8.0', 'mcp-config', serverResults);
    expect(payload.mcpEnumeration!.totalTools).toBe(8);
  });

  it('counts dangerous tools', () => {
    const payload = buildMcpContribution('0.8.0', 'mcp-config', serverResults);
    expect(payload.mcpEnumeration!.dangerousToolCount).toBe(3);
  });

  it('does not include server names', () => {
    const payload = buildMcpContribution('0.8.0', 'mcp-config', serverResults);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('server-a');
    expect(serialized).not.toContain('server-b');
  });

  it('deduplicates finding IDs', () => {
    const duplicateResults = [
      {
        serverName: 's1',
        toolCount: 2,
        findings: [
          { checkId: 'MCPTOOL-001', severity: 'critical' },
          { checkId: 'MCPTOOL-001', severity: 'critical' },
        ],
      },
    ];
    const payload = buildMcpContribution('0.8.0', 'config', duplicateResults);
    expect(payload.findingIds).toEqual(['MCPTOOL-001']);
  });
});

// ---------------------------------------------------------------------------
// buildAttackContribution
// ---------------------------------------------------------------------------
describe('buildAttackContribution', () => {
  const attackReport = {
    categories: ['prompt-injection', 'jailbreak'],
    totalPayloads: 20,
    blocked: 15,
    bypassed: 5,
    blockRate: 0.75,
  };

  it('includes block rate', () => {
    const payload = buildAttackContribution('0.8.0', 'target-hash', attackReport);
    expect(payload.attack).toBeDefined();
    expect(payload.attack!.blockRate).toBe(0.75);
  });

  it('includes payload counts', () => {
    const payload = buildAttackContribution('0.8.0', 'target-hash', attackReport);
    expect(payload.attack!.payloadsRun).toBe(20);
    expect(payload.attack!.payloadsBlocked).toBe(15);
    expect(payload.attack!.payloadsBypassed).toBe(5);
  });

  it('includes categories', () => {
    const payload = buildAttackContribution('0.8.0', 'target-hash', attackReport);
    expect(payload.attack!.categories).toContain('prompt-injection');
    expect(payload.attack!.categories).toContain('jailbreak');
  });

  it('maps bypassed count to totalFindings', () => {
    const payload = buildAttackContribution('0.8.0', 'target-hash', attackReport);
    expect(payload.totalFindings).toBe(5);
    expect(payload.highCount).toBe(5);
  });

  it('includes scanDurationMs when provided', () => {
    const payload = buildAttackContribution('0.8.0', 'target-hash', attackReport, 3500);
    expect(payload.scanDurationMs).toBe(3500);
  });
});

// ---------------------------------------------------------------------------
// submitContribution
// ---------------------------------------------------------------------------
describe('submitContribution', () => {
  const samplePayload: ContributionPayload = {
    contributionId: '00000000-0000-0000-0000-000000000001',
    artifactHash: 'a'.repeat(64),
    scanType: 'hardening',
    scannerVersion: '0.8.0',
    scanTimestamp: '2026-03-03T00:00:00.000Z',
    totalFindings: 1,
    criticalCount: 1,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    findingIds: ['SHELL-001'],
    score: 72,
    maxScore: 100,
  };

  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('handles success response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'accepted', message: 'Contribution received' }),
    });

    const result = await submitContribution('https://registry.opena2a.org', samplePayload);
    expect(result.status).toBe('accepted');
    expect(result.message).toBe('Contribution received');

    expect(globalThis.fetch).toHaveBeenCalledWith(
      'https://registry.opena2a.org/api/v1/registry/community/contribute',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'User-Agent': 'HackMyAgent-CLI',
        }),
      }),
    );
  });

  it('handles HTTP error response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: async () => ({ message: 'Invalid payload' }),
    });

    const result = await submitContribution('https://registry.opena2a.org', samplePayload);
    expect(result.status).toBe('failed');
    expect(result.message).toBe('Invalid payload');
  });

  it('handles HTTP error with no JSON body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => { throw new Error('not JSON'); },
    });

    const result = await submitContribution('https://registry.opena2a.org', samplePayload);
    expect(result.status).toBe('failed');
    expect(result.message).toBe('HTTP 500');
  });

  it('handles network error', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await submitContribution('https://registry.opena2a.org', samplePayload);
    expect(result.status).toBe('failed');
    expect(result.message).toBe('Network error');
  });

  it('never throws', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));

    // Should resolve, not reject
    const result = await submitContribution('https://registry.opena2a.org', samplePayload);
    expect(result).toBeDefined();
    expect(result.status).toBe('failed');
  });
});

// ---------------------------------------------------------------------------
// PII Safety Checks
// ---------------------------------------------------------------------------
describe('PII safety', () => {
  it('contribution payload NEVER contains file paths', () => {
    const artifactContent = '/Users/johndoe/project/.cursor/mcp.json';
    const findings = [
      { checkId: 'SHELL-001', severity: 'critical', passed: false },
    ];
    const payload = buildHardeningContribution('0.8.0', artifactContent, findings, 50, 100);
    const serialized = JSON.stringify(payload);

    // The file path should be hashed, not present as plaintext
    expect(serialized).not.toContain('/Users/johndoe');
    expect(serialized).not.toContain('.cursor');
    expect(serialized).not.toContain('mcp.json');

    // But the hash of the path should be present
    expect(payload.artifactHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('contribution payload NEVER contains hostnames', () => {
    const artifactContent = 'host: my-secret-server.internal.corp.com';
    const payload = buildAttackContribution(
      '0.8.0',
      artifactContent,
      { categories: ['prompt-injection'], totalPayloads: 1, blocked: 0, bypassed: 1, blockRate: 0 },
    );
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain('my-secret-server');
    expect(serialized).not.toContain('internal.corp.com');
  });

  it('contribution payload NEVER contains environment variable values', () => {
    const artifactContent = 'OPENAI_API_KEY=sk-1234567890abcdef';
    const findings = [
      { checkId: 'CRED-001', severity: 'critical', passed: false },
    ];
    const payload = buildHardeningContribution('0.8.0', artifactContent, findings, 20, 100);
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain('sk-1234567890abcdef');
    expect(serialized).not.toContain('OPENAI_API_KEY');
  });

  it('governance contribution does not leak file content', () => {
    const artifactContent = 'This agent is owned by John Smith at john@company.com';
    const governanceScore = {
      overall: 40,
      grade: 'D',
      tier: 'Tier 3',
      domains: [{ domain: 'transparency', score: 40, controlsPassed: 1, controlsTotal: 3 }],
      results: [{ controlId: 'GOV-001', severity: 'critical', passed: false }],
      criticalFailures: ['GOV-001'],
    };
    const payload = buildGovernanceContribution('0.8.0', artifactContent, governanceScore);
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain('John Smith');
    expect(serialized).not.toContain('john@company.com');
    expect(serialized).not.toContain('This agent is owned');
  });

  it('MCP contribution does not leak server names or config paths', () => {
    const configContent = '{"mcpServers":{"my-private-db":{"command":"node","args":["/opt/secret/db.js"]}}}';
    const serverResults = [
      {
        serverName: 'my-private-db',
        toolCount: 3,
        findings: [{ checkId: 'MCPTOOL-001', severity: 'critical' }],
      },
    ];
    const payload = buildMcpContribution('0.8.0', configContent, serverResults);
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain('my-private-db');
    expect(serialized).not.toContain('/opt/secret/db.js');
    expect(serialized).not.toContain('mcpServers');
  });
});
