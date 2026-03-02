import { describe, it, expect } from 'vitest';
import { toSecurityFinding, toSecurityFindings } from '../../src/semantic/integration/finding-adapter';
import type { SemanticFinding } from '../../src/semantic/types';

describe('FindingAdapter', () => {
  const sampleFinding: SemanticFinding = {
    id: 'SEM-CRED-001',
    title: 'Password embedded in URL',
    description: 'Database URL contains inline password.',
    rationale: 'URL passwords are logged by proxies.',
    category: 'credential',
    severity: 'critical',
    file: '.env',
    line: 3,
    recommendation: 'Use env vars instead.',
    layer: 2,
    autoFixable: false,
  };

  it('converts SemanticFinding to SecurityFinding', () => {
    const result = toSecurityFinding(sampleFinding);
    expect(result.checkId).toBe('SEM-CRED-001');
    expect(result.name).toBe('Password embedded in URL');
    expect(result.severity).toBe('critical');
    expect(result.passed).toBe(false);
    expect(result.fixable).toBe(false);
    expect(result.file).toBe('.env');
    expect(result.line).toBe(3);
    expect(result.fix).toBe('Use env vars instead.');
    expect(result.category).toBe('Credential Protection');
  });

  it('maps category labels correctly', () => {
    const mcpFinding: SemanticFinding = { ...sampleFinding, id: 'SEM-MCP-001', category: 'mcp-config' };
    const instFinding: SemanticFinding = { ...sampleFinding, id: 'SEM-INST-001', category: 'instruction' };
    const permFinding: SemanticFinding = { ...sampleFinding, id: 'SEM-PERM-001', category: 'permission' };

    expect(toSecurityFinding(mcpFinding).category).toBe('MCP Configuration');
    expect(toSecurityFinding(instFinding).category).toBe('Agent Instructions');
    expect(toSecurityFinding(permFinding).category).toBe('Permission Model');
  });

  it('converts info severity to low', () => {
    const infoFinding: SemanticFinding = { ...sampleFinding, severity: 'info' };
    expect(toSecurityFinding(infoFinding).severity).toBe('low');
  });

  it('converts array of findings', () => {
    const results = toSecurityFindings([sampleFinding, { ...sampleFinding, id: 'SEM-CRED-002' }]);
    expect(results).toHaveLength(2);
    expect(results[0].checkId).toBe('SEM-CRED-001');
    expect(results[1].checkId).toBe('SEM-CRED-002');
  });

  it('preserves all fields', () => {
    const result = toSecurityFinding(sampleFinding);
    expect(result.message).toBe('URL passwords are logged by proxies.');
    expect(result.description).toBe('Database URL contains inline password.');
  });
});
