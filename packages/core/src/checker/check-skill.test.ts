import { describe, it, expect } from 'vitest';
import { checkSkill, CheckResult, RiskLevel } from './check-skill';

describe('checkSkill', () => {
  it('returns a check result with publisher, permissions, and revocation status', async () => {
    const result = await checkSkill('@opena2a/security');

    expect(result).toMatchObject({
      skillId: '@opena2a/security',
      publisher: expect.any(Object),
      permissions: expect.any(Object),
      revocation: expect.any(Object),
      risk: expect.any(String),
    });
  });

  it('identifies unverified publisher as higher risk', async () => {
    // Unknown publisher with no verification
    const result = await checkSkill('@unknown-dev/sketchy-tool');

    expect(result.publisher.verified).toBe(false);
    expect(['medium', 'high', 'critical']).toContain(result.risk);
  });

  it('flags dangerous permissions', async () => {
    // Skill requesting shell access should be flagged
    const result = await checkSkill('@test/shell-skill', {
      manifest: {
        permissions: ['shell:execute', 'filesystem:*'],
      },
    });

    expect(result.permissions.dangerous).toContain('shell:execute');
    expect(result.permissions.dangerous).toContain('filesystem:*');
    expect(result.risk).toBe('high');
  });

  it('checks revocation status', async () => {
    const result = await checkSkill('@opena2a/security');

    expect(result.revocation).toMatchObject({
      revoked: expect.any(Boolean),
      checkedAt: expect.any(Date),
    });
  });

  it('returns critical risk for revoked skills', async () => {
    const result = await checkSkill('@malicious/bad-skill', {
      mockRevoked: true,
    });

    expect(result.revocation.revoked).toBe(true);
    expect(result.risk).toBe('critical');
  });
});

describe('RiskLevel calculation', () => {
  it('is low when publisher verified and permissions minimal', async () => {
    const result = await checkSkill('@verified/safe-skill', {
      mockVerified: true,
      manifest: {
        permissions: ['messages:read'],
      },
    });

    expect(result.risk).toBe('low');
  });

  it('is medium when publisher unverified but permissions safe', async () => {
    const result = await checkSkill('@unverified/safe-skill', {
      mockVerified: false,
      manifest: {
        permissions: ['messages:read'],
      },
    });

    expect(result.risk).toBe('medium');
  });

  it('is high when dangerous permissions requested', async () => {
    const result = await checkSkill('@verified/risky-skill', {
      mockVerified: true,
      manifest: {
        permissions: ['shell:execute'],
      },
    });

    expect(result.risk).toBe('high');
  });

  it('is critical when skill is revoked', async () => {
    const result = await checkSkill('@any/revoked-skill', {
      mockRevoked: true,
    });

    expect(result.risk).toBe('critical');
  });
});
