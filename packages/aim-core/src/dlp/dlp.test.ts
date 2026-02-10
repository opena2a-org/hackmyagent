import { describe, it, expect } from 'vitest';
import { scanText, maskMetadata, ALL_PATTERNS, PII_PATTERNS, SECRET_PATTERNS } from './index';
import { mask } from './masking';
import { getDLPAction, defaultDLPPolicy } from './policy';
import type { DLPPolicy, DLPPattern } from './types';

describe('PII Detection', () => {
  it('detects SSN', () => {
    const result = scanText('My SSN is 123-45-6789');
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].patternId).toBe('pii-ssn');
    expect(result.matches[0].severity).toBe('critical');
  });

  it('detects email addresses', () => {
    const result = scanText('Contact me at user@example.com for details');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'pii-email')).toBe(true);
  });

  it('detects US phone numbers', () => {
    const result = scanText('Call me at 555-123-4567');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'pii-phone-us')).toBe(true);
  });

  it('detects credit card numbers', () => {
    const result = scanText('Card: 4111-1111-1111-1111');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'pii-credit-card')).toBe(true);
  });

  it('detects multiple PII in one text', () => {
    const text = 'Name: John, SSN: 123-45-6789, Email: john@example.com, Phone: 555-987-6543';
    const result = scanText(text);
    expect(result.matches.length).toBeGreaterThanOrEqual(3);
  });

  it('returns clean text when no PII found', () => {
    const result = scanText('This is a normal sentence with no sensitive data.');
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
    expect(result.action).toBe('allowed');
  });
});

describe('Secret Detection', () => {
  it('detects Anthropic API key', () => {
    const result = scanText('key: sk-ant-api03-abc123def456ghi789jkl012mno345');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-anthropic')).toBe(true);
  });

  it('detects OpenAI API key', () => {
    const result = scanText('OPENAI_KEY=sk-proj1234567890abcdefghijklmnop');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-openai')).toBe(true);
  });

  it('detects AWS access key', () => {
    const result = scanText('aws_key = AKIAIOSFODNN7EXAMPLE');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-aws-key')).toBe(true);
  });

  it('detects GitHub PAT', () => {
    const result = scanText('token: ghp_abcdefghijklmnopqrstuvwxyz0123456789AB');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-github-pat')).toBe(true);
  });

  it('detects private key header', () => {
    const result = scanText('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-private-key')).toBe(true);
  });

  it('detects Stripe key', () => {
    const result = scanText('sk_live_' + 'abcdefghijklmnopqrstuvwx');
    expect(result.detected).toBe(true);
    expect(result.matches.some((m) => m.patternId === 'secret-stripe')).toBe(true);
  });
});

describe('Masking', () => {
  const testPattern: DLPPattern = {
    id: 'test-full',
    name: 'Test Full',
    regex: /test/g,
    severity: 'high',
    category: 'pii',
    maskStrategy: 'full',
  };

  it('full mask replaces entirely', () => {
    const result = mask('sensitive-value', testPattern);
    expect(result).toBe('[REDACTED:test-full]');
    expect(result).not.toContain('sensitive');
  });

  it('partial mask shows first and last 4 chars', () => {
    const partialPattern = { ...testPattern, id: 'test-partial', maskStrategy: 'partial' as const };
    const result = mask('1234567890abcdef', partialPattern);
    expect(result).toBe('1234***cdef');
  });

  it('partial mask falls back to full for short values', () => {
    const partialPattern = { ...testPattern, id: 'test-partial', maskStrategy: 'partial' as const };
    const result = mask('short', partialPattern);
    expect(result).toBe('[REDACTED:test-partial]');
  });

  it('hash mask produces deterministic hash', () => {
    const hashPattern = { ...testPattern, id: 'test-hash', maskStrategy: 'hash' as const };
    const result1 = mask('same-value', hashPattern);
    const result2 = mask('same-value', hashPattern);
    expect(result1).toBe(result2);
    expect(result1).toMatch(/^\[HASH:test-hash:[a-f0-9]{8}\]$/);
  });

  it('masked text replaces all detections', () => {
    const result = scanText('SSN: 123-45-6789, another: 987-65-4321');
    expect(result.maskedText).not.toContain('123-45-6789');
    expect(result.maskedText).not.toContain('987-65-4321');
  });
});

describe('DLP Policy', () => {
  it('uses default policy when none provided', () => {
    const pattern: DLPPattern = {
      id: 'test', name: 'Test', regex: /x/g,
      severity: 'high', category: 'credential', maskStrategy: 'full',
    };
    const action = getDLPAction(pattern);
    expect(action).toBe('block'); // credentials are blocked by default
  });

  it('allows infrastructure patterns by default', () => {
    const pattern: DLPPattern = {
      id: 'test', name: 'Test', regex: /x/g,
      severity: 'low', category: 'infrastructure', maskStrategy: 'partial',
    };
    const action = getDLPAction(pattern);
    expect(action).toBe('allow');
  });

  it('respects per-pattern override', () => {
    const policy: DLPPolicy = {
      enabled: true,
      defaultAction: 'block',
      patterns: { 'pii-email': 'allow' },
    };
    const emailPattern = PII_PATTERNS.find((p) => p.id === 'pii-email')!;
    expect(getDLPAction(emailPattern, policy)).toBe('allow');
  });

  it('respects per-category override', () => {
    const policy: DLPPolicy = {
      enabled: true,
      defaultAction: 'block',
      categories: { pii: 'mask' },
    };
    const ssnPattern = PII_PATTERNS.find((p) => p.id === 'pii-ssn')!;
    expect(getDLPAction(ssnPattern, policy)).toBe('mask');
  });

  it('returns allow when DLP is disabled', () => {
    const policy: DLPPolicy = { enabled: false, defaultAction: 'block' };
    const pattern: DLPPattern = {
      id: 'test', name: 'Test', regex: /x/g,
      severity: 'critical', category: 'credential', maskStrategy: 'full',
    };
    expect(getDLPAction(pattern, policy)).toBe('allow');
  });

  it('blocked action when credential detected with default policy', () => {
    const result = scanText('sk-ant-api03-abc123def456ghi789jkl012mno345');
    expect(result.action).toBe('blocked');
  });

  it('masked action when PII detected with default policy', () => {
    const result = scanText('SSN: 123-45-6789', { patterns: PII_PATTERNS });
    expect(result.action).toBe('masked');
  });

  it('creates default policy', () => {
    const policy = defaultDLPPolicy();
    expect(policy.enabled).toBe(true);
    expect(policy.defaultAction).toBe('mask');
  });
});

describe('maskMetadata', () => {
  it('masks PII in metadata string values', () => {
    const metadata = {
      prompt: 'My SSN is 123-45-6789',
      count: 42,
      nested: { email: 'user@example.com' },
    };
    const masked = maskMetadata(metadata);

    expect(masked.prompt).not.toContain('123-45-6789');
    expect(masked.count).toBe(42);
    expect((masked.nested as Record<string, unknown>).email).not.toContain('user@example.com');
  });

  it('leaves clean metadata unchanged', () => {
    const metadata = { action: 'read', target: '/tmp/file.txt' };
    const masked = maskMetadata(metadata);
    expect(masked).toEqual(metadata);
  });

  it('handles empty metadata', () => {
    const masked = maskMetadata({});
    expect(masked).toEqual({});
  });
});

describe('Pattern Coverage', () => {
  it('has PII patterns', () => {
    expect(PII_PATTERNS.length).toBeGreaterThanOrEqual(5);
  });

  it('has secret patterns', () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(8);
  });

  it('ALL_PATTERNS includes both', () => {
    expect(ALL_PATTERNS.length).toBe(PII_PATTERNS.length + SECRET_PATTERNS.length);
  });

  it('all patterns have unique IDs', () => {
    const ids = ALL_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
