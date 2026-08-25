/**
 * #458 step 0 — a benchmark run that measured nothing carries `compliance:
 * null`; the publish summary must say so rather than print `null% compliance`.
 * Nothing populates `oasbResult` on a CLI path today, so this is the library
 * surface pinned directly.
 */
import { describe, it, expect } from 'vitest';
import { formatPublishOutput } from '../../src/registry/publish';

const result = { success: true, scanId: 'scan-1', profileUrl: '', status: 'accepted', isCommunity: false };

describe('formatPublishOutput over a null benchmark compliance', () => {
  it('RED-ON-BASE prints "compliance not measured", never null%', () => {
    const out = formatPublishOutput(result as any, { packageName: 'p', oasbResult: { compliance: null, rating: 'Not Assessed' } } as any, 'https://api.oa2a.org');
    expect(out).toContain('OASB (compliance not measured)');
    expect(out).not.toContain('null');
  });

  it('PIN: a measured compliance still prints its figure', () => {
    const out = formatPublishOutput(result as any, { packageName: 'p', oasbResult: { compliance: 94, rating: 'Passing' } } as any, 'https://api.oa2a.org');
    expect(out).toContain('OASB (94% compliance)');
  });
});
