import { describe, it, expect } from 'vitest';
import { analyzePermissions, PermissionAnalysis } from './permission-analyzer';

describe('analyzePermissions', () => {
  it('categorizes safe permissions', () => {
    const result = analyzePermissions(['messages:read', 'config:read']);

    expect(result.safe).toContain('messages:read');
    expect(result.safe).toContain('config:read');
    expect(result.dangerous).toHaveLength(0);
    expect(result.riskScore).toBeLessThan(30);
  });

  it('categorizes dangerous permissions', () => {
    const result = analyzePermissions(['shell:execute', 'filesystem:*', 'network:*']);

    expect(result.dangerous).toContain('shell:execute');
    expect(result.dangerous).toContain('filesystem:*');
    expect(result.dangerous).toContain('network:*');
    expect(result.riskScore).toBeGreaterThan(70);
  });

  it('categorizes review-needed permissions', () => {
    const result = analyzePermissions(['filesystem:~/Documents', 'network:api.example.com']);

    expect(result.reviewNeeded).toContain('filesystem:~/Documents');
    expect(result.reviewNeeded).toContain('network:api.example.com');
    expect(result.riskScore).toBeGreaterThan(30);
    expect(result.riskScore).toBeLessThan(70);
  });

  it('flags wildcard permissions as dangerous', () => {
    const result = analyzePermissions(['mcp:*']);

    expect(result.dangerous).toContain('mcp:*');
  });

  it('returns empty arrays for no permissions', () => {
    const result = analyzePermissions([]);

    expect(result.safe).toHaveLength(0);
    expect(result.dangerous).toHaveLength(0);
    expect(result.reviewNeeded).toHaveLength(0);
    expect(result.riskScore).toBe(0);
  });

  it('calculates risk score based on permission severity', () => {
    const safeOnly = analyzePermissions(['messages:read']);
    const mixed = analyzePermissions(['messages:read', 'filesystem:~/Downloads']);
    const dangerous = analyzePermissions(['shell:execute', 'filesystem:*']);

    expect(safeOnly.riskScore).toBeLessThan(mixed.riskScore);
    expect(mixed.riskScore).toBeLessThan(dangerous.riskScore);
  });
});

describe('permission patterns', () => {
  it('recognizes shell permissions as dangerous', () => {
    const result = analyzePermissions(['shell:execute', 'shell:read']);

    expect(result.dangerous).toContain('shell:execute');
    expect(result.dangerous).toContain('shell:read');
  });

  it('recognizes broad filesystem access as dangerous', () => {
    const result = analyzePermissions(['filesystem:*', 'filesystem:/', 'filesystem:~']);

    result.dangerous.forEach((p) => {
      expect(p).toMatch(/^filesystem:/);
    });
    expect(result.dangerous.length).toBe(3);
  });

  it('recognizes scoped filesystem access as review-needed', () => {
    const result = analyzePermissions([
      'filesystem:~/Documents',
      'filesystem:~/.config/myapp',
    ]);

    expect(result.reviewNeeded).toContain('filesystem:~/Documents');
    expect(result.reviewNeeded).toContain('filesystem:~/.config/myapp');
    expect(result.dangerous).toHaveLength(0);
  });

  it('recognizes broad network access as dangerous', () => {
    const result = analyzePermissions(['network:*']);

    expect(result.dangerous).toContain('network:*');
  });

  it('recognizes scoped network access as review-needed', () => {
    const result = analyzePermissions(['network:api.github.com', 'network:example.com']);

    expect(result.reviewNeeded).toContain('network:api.github.com');
    expect(result.reviewNeeded).toContain('network:example.com');
  });

  it('recognizes mcp wildcard as dangerous', () => {
    const result = analyzePermissions(['mcp:*']);

    expect(result.dangerous).toContain('mcp:*');
  });

  it('recognizes specific mcp access as review-needed', () => {
    const result = analyzePermissions(['mcp:github', 'mcp:filesystem']);

    expect(result.reviewNeeded).toContain('mcp:github');
    expect(result.reviewNeeded).toContain('mcp:filesystem');
  });
});
