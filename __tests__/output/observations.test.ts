import { describe, it, expect } from 'vitest';
import {
  buildCategorySummaries,
  buildVerdict,
  classifyCategory,
  renderObservationsBlock,
  ALL_CATEGORY_LABELS,
} from '../../src/output/observations';
import type { SecurityFinding } from '../../src/hardening/security-check';

function finding(over: Partial<SecurityFinding>): SecurityFinding {
  return {
    checkId: '',
    name: '',
    description: '',
    category: '',
    severity: 'low',
    passed: false,
    message: '',
    fixable: false,
    ...over,
  } as SecurityFinding;
}

describe('classifyCategory', () => {
  it('classifies by checkId prefix', () => {
    expect(classifyCategory(finding({ checkId: 'CRED-001' }))).toBe('credentials');
    expect(classifyCategory(finding({ checkId: 'MCP-003' }))).toBe('MCP');
    expect(classifyCategory(finding({ checkId: 'NEMO-007' }))).toBe('sandbox-escape');
    expect(classifyCategory(finding({ checkId: 'AST-GOV-004' }))).toBe('governance');
    expect(classifyCategory(finding({ checkId: 'UNICODE-STEGO-001' }))).toBe('unicode-stego');
  });

  it('falls back to name/category keywords when checkId has no known prefix', () => {
    expect(
      classifyCategory(finding({ checkId: 'X', name: 'Hardcoded API key in source' })),
    ).toBe('credentials');
    expect(
      classifyCategory(finding({ checkId: 'X', category: 'mcp-config' })),
    ).toBe('MCP');
  });

  it('returns null when nothing matches', () => {
    expect(classifyCategory(finding({ checkId: 'UNKNOWN-XYZ', name: 'Nothing to see' }))).toBeNull();
  });
});

describe('buildCategorySummaries', () => {
  it('marks all categories clear for zero findings', () => {
    const summaries = buildCategorySummaries([]);
    expect(summaries.length).toBeGreaterThanOrEqual(ALL_CATEGORY_LABELS.length);
    for (const s of summaries) {
      expect(s.clear).toBe(true);
      expect(s.counts.critical + s.counts.high + s.counts.medium + s.counts.low).toBe(0);
    }
  });

  it('counts severity for matching findings and marks matched category dirty', () => {
    const summaries = buildCategorySummaries([
      finding({ checkId: 'CRED-001', severity: 'critical' }),
      finding({ checkId: 'CRED-002', severity: 'critical' }),
      finding({ checkId: 'MCP-003', severity: 'high' }),
    ]);
    const cred = summaries.find(s => s.name === 'credentials')!;
    const mcp = summaries.find(s => s.name === 'MCP')!;
    const network = summaries.find(s => s.name === 'network')!;
    expect(cred.clear).toBe(false);
    expect(cred.counts.critical).toBe(2);
    expect(mcp.clear).toBe(false);
    expect(mcp.counts.high).toBe(1);
    expect(network.clear).toBe(true);
  });

  it('groups unrecognized findings into "other" bucket', () => {
    const summaries = buildCategorySummaries([
      finding({ checkId: 'UNKNOWN-999', severity: 'critical' }),
    ]);
    const other = summaries.find(s => s.name === 'other');
    expect(other).toBeDefined();
    expect(other!.clear).toBe(false);
    expect(other!.counts.critical).toBe(1);
  });

  it('ignores passed findings', () => {
    const summaries = buildCategorySummaries([
      finding({ checkId: 'CRED-001', severity: 'critical', passed: true }),
    ]);
    const cred = summaries.find(s => s.name === 'credentials')!;
    expect(cred.clear).toBe(true);
    expect(cred.counts.critical).toBe(0);
  });
});

describe('buildVerdict', () => {
  it('unsafe verdict names the lead critical finding with file:line', () => {
    const v = buildVerdict(
      { critical: 3, high: 0, medium: 0, low: 0 },
      { kind: 'library' },
      [
        { severity: 'critical', name: 'Hardcoded API key', file: '.env', line: 3 },
        { severity: 'critical', name: 'Weak PERM', file: 'config.json' },
        { severity: 'critical', name: 'Open Port', file: 'server.ts' },
      ],
    );
    expect(v.status).toBe('unsafe');
    expect(v.message).toContain('Hardcoded API key in .env:3');
    expect(v.message).toContain('+ 2 more');
    expect(v.message).toContain('production');
  });

  it('unsafe verdict on high names the lead high finding', () => {
    const v = buildVerdict(
      { critical: 0, high: 2, medium: 0, low: 0 },
      { kind: 'library' },
      [
        { severity: 'high', name: 'Unsafe eval', file: 'deploy.skill.md', line: 4 },
        { severity: 'high', name: 'Broad MCP scope', file: 'mcp.json' },
      ],
    );
    expect(v.status).toBe('unsafe');
    expect(v.message).toContain('Unsafe eval in deploy.skill.md:4');
    expect(v.message).toContain('+ 1 more');
  });

  it('needs-fix verdict names the lead medium/low finding', () => {
    const v = buildVerdict(
      { critical: 0, high: 0, medium: 2, low: 3 },
      { kind: 'library' },
      [
        { severity: 'medium', name: 'Missing audit log', file: 'app.ts' },
        { severity: 'medium', name: 'Weak rate limit', file: 'api.ts' },
        { severity: 'low', name: 'Missing .gitignore', file: '.gitignore' },
        { severity: 'low', name: 'Broad perms', file: 'config.json' },
        { severity: 'low', name: 'No audit trail', file: 'log.ts' },
      ],
    );
    expect(v.status).toBe('needs-fix');
    expect(v.message).toContain('Missing audit log in app.ts');
    expect(v.message).toContain('+ 4 more');
    expect(v.message).toContain('secure --fix');
  });

  it('safe verdict on zero findings', () => {
    const v = buildVerdict({ critical: 0, high: 0, medium: 0, low: 0 }, { kind: 'library' });
    expect(v.status).toBe('safe');
    expect(v.message).toMatch(/safe to use/i);
    expect(v.message).toContain('library');
  });

  it('safe verdict falls back to "project" when kind is unknown', () => {
    const v = buildVerdict({ critical: 0, high: 0, medium: 0, low: 0 }, { kind: 'unknown' });
    expect(v.message).toContain('project');
  });

  it('falls back to severity-count when findings array not passed', () => {
    const v = buildVerdict({ critical: 2, high: 0, medium: 0, low: 0 }, { kind: 'library' });
    expect(v.status).toBe('unsafe');
    expect(v.message).toContain('2 critical');
  });

  it('falls back to checkId when finding name is empty', () => {
    const v = buildVerdict(
      { critical: 1, high: 0, medium: 0, low: 0 },
      { kind: 'library' },
      [{ severity: 'critical', checkId: 'CRED-001', file: 'secret.ts' }],
    );
    expect(v.message).toContain('CRED-001 in secret.ts');
  });

  it('no extra count when there is exactly one finding', () => {
    const v = buildVerdict(
      { critical: 1, high: 0, medium: 0, low: 0 },
      { kind: 'library' },
      [{ severity: 'critical', name: 'API key exposed', file: '.env', line: 2 }],
    );
    expect(v.message).toContain('API key exposed in .env:2');
    expect(v.message).not.toContain('+ ');
  });
});

describe('renderObservationsBlock with artifacts', () => {
  const base = {
    surfaces: { kind: 'library', filesScanned: 4, artifactsCompiled: 2 },
    checks: { staticCount: 209, semanticCount: 2 },
    categories: buildCategorySummaries([]),
    verdict: buildVerdict({ critical: 0, high: 0, medium: 0, low: 0 }, { kind: 'library' }),
  };

  it('artifacts block empty when no artifacts passed', () => {
    const out = renderObservationsBlock(base);
    expect(out.artifactLines).toEqual([]);
  });

  it('artifacts block empty when artifacts array is empty', () => {
    const out = renderObservationsBlock({ ...base, artifacts: [] });
    expect(out.artifactLines).toEqual([]);
  });

  it('renders one line per artifact', () => {
    const out = renderObservationsBlock({
      ...base,
      artifacts: [
        { path: 'deploy.skill.md', type: 'skill', intent: 'benign', capabilityLabels: ['fs-write', 'net-egress'], constraintCount: 3, weakConstraintCount: 0 },
        { path: 'mcp.json', type: 'mcp_config', intent: 'suspicious', capabilityLabels: ['shell-exec'], constraintCount: 0, weakConstraintCount: 0 },
      ],
    });
    // Output order: suspicious before benign (intent-ranked).
    expect(out.artifactLines).toHaveLength(2);
    const joined = out.artifactLines.join('\n');
    expect(joined).toContain('deploy.skill.md');
    expect(joined).toContain('skill');
    expect(joined).toContain('benign');
    expect(joined).toContain('fs-write + net-egress');
    expect(joined).toContain('3 constraints');
    expect(joined).toContain('mcp.json');
    expect(joined).toContain('shell-exec');
    expect(joined).toContain('no declared constraints');
    // Suspicious comes first
    expect(out.artifactLines[0]).toContain('mcp.json');
  });

  it('sorts artifacts by intent severity (malicious first) then capability count', () => {
    const out = renderObservationsBlock({
      ...base,
      artifacts: [
        { path: 'a.skill.md', type: 'skill', intent: 'benign', capabilityLabels: [], constraintCount: 0, weakConstraintCount: 0 },
        { path: 'b.skill.md', type: 'skill', intent: 'malicious', capabilityLabels: ['fs-write'], constraintCount: 0, weakConstraintCount: 0 },
        { path: 'c.skill.md', type: 'skill', intent: 'suspicious', capabilityLabels: ['net-egress'], constraintCount: 0, weakConstraintCount: 0 },
      ],
    });
    expect(out.artifactLines[0]).toContain('b.skill.md');        // malicious
    expect(out.artifactLines[1]).toContain('c.skill.md');        // suspicious
    expect(out.artifactLines[2]).toContain('a.skill.md');        // benign
  });

  it('caps at 6 lines in default mode and appends "+ N more" tail', () => {
    const arts = Array.from({ length: 10 }, (_, i) => ({
      path: `skill-${i}.md`,
      type: 'skill',
      intent: 'benign' as const,
      capabilityLabels: ['fs-read'],
      constraintCount: 1,
      weakConstraintCount: 0,
    }));
    const out = renderObservationsBlock({ ...base, artifacts: arts });
    expect(out.artifactLines).toHaveLength(7); // 6 artifacts + 1 tail
    expect(out.artifactLines[6]).toContain('+ 4 more');
    expect(out.artifactLines[6]).toContain('--verbose');
  });

  it('verbose mode shows all artifacts with no tail', () => {
    const arts = Array.from({ length: 10 }, (_, i) => ({
      path: `skill-${i}.md`,
      type: 'skill',
      intent: 'benign' as const,
      capabilityLabels: ['fs-read'],
      constraintCount: 1,
      weakConstraintCount: 0,
    }));
    const out = renderObservationsBlock({ ...base, artifacts: arts, verbose: true });
    expect(out.artifactLines).toHaveLength(10);
    expect(out.artifactLines.every(l => !l.includes('+ '))).toBe(true);
  });

  it('names weak constraints when present', () => {
    const out = renderObservationsBlock({
      ...base,
      artifacts: [
        { path: 'SOUL.md', type: 'soul', intent: 'benign', capabilityLabels: [], constraintCount: 5, weakConstraintCount: 2 },
      ],
    });
    expect(out.artifactLines[0]).toContain('5 constraints, 2 weak');
  });
});

describe('renderObservationsBlock', () => {
  const zeroFindingsInput = {
    surfaces: { kind: 'library', filesScanned: 2, artifactsCompiled: 2 },
    checks: { staticCount: 209, semanticCount: 2 },
    categories: buildCategorySummaries([]),
    verdict: buildVerdict({ critical: 0, high: 0, medium: 0, low: 0 }, { kind: 'library' }),
  };

  it('emits 4 lines in the fixed order', () => {
    const { lines } = renderObservationsBlock(zeroFindingsInput);
    expect(lines.map(l => l.label)).toEqual(['Surfaces', 'Checks', 'Categories', 'Verdict']);
  });

  it('zero-findings Categories line marks all clear', () => {
    const { lines } = renderObservationsBlock(zeroFindingsInput);
    const cat = lines.find(l => l.label === 'Categories')!;
    expect(cat.value).toContain('all clear');
    expect(cat.tone).toBe('good');
  });

  it('findings Categories line groups dirty buckets with severity and collapses clear count', () => {
    const findings = [
      finding({ checkId: 'CRED-001', severity: 'critical' }),
      finding({ checkId: 'MCP-003', severity: 'high' }),
    ];
    const { lines } = renderObservationsBlock({
      ...zeroFindingsInput,
      categories: buildCategorySummaries(findings),
      verdict: buildVerdict({ critical: 1, high: 1, medium: 0, low: 0 }, { kind: 'library' }),
    });
    const cat = lines.find(l => l.label === 'Categories')!;
    expect(cat.value).toContain('credentials (1 critical)');
    expect(cat.value).toContain('MCP (1 high)');
    expect(cat.value).toMatch(/others clear/);
    expect(cat.tone).toBe('warning');
  });

  it('Verdict tone reflects verdict status', () => {
    const unsafe = renderObservationsBlock({
      ...zeroFindingsInput,
      verdict: buildVerdict({ critical: 1, high: 0, medium: 0, low: 0 }, { kind: 'library' }),
    });
    expect(unsafe.lines.find(l => l.label === 'Verdict')!.tone).toBe('critical');

    const needsFix = renderObservationsBlock({
      ...zeroFindingsInput,
      verdict: buildVerdict({ critical: 0, high: 0, medium: 0, low: 1 }, { kind: 'library' }),
    });
    expect(needsFix.lines.find(l => l.label === 'Verdict')!.tone).toBe('warning');

    const safe = renderObservationsBlock(zeroFindingsInput);
    expect(safe.lines.find(l => l.label === 'Verdict')!.tone).toBe('good');
  });

  it('Checks line includes skipped detail when present', () => {
    const { lines } = renderObservationsBlock({
      ...zeroFindingsInput,
      checks: {
        staticCount: 209,
        semanticCount: 2,
        skipped: [{ category: 'ARP', reason: 'requires --deep' }],
      },
    });
    const checks = lines.find(l => l.label === 'Checks')!;
    expect(checks.value).toContain('1 skipped');
    expect(checks.value).toContain('ARP — requires --deep');
  });

  it('verbose mode expands Categories list', () => {
    const { lines } = renderObservationsBlock({ ...zeroFindingsInput, verbose: true });
    const cat = lines.find(l => l.label === 'Categories')!;
    expect(cat.value).not.toContain('+ ');
    expect(cat.value).toContain('all clear');
  });
});
