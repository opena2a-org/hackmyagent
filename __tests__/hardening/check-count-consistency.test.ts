import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { getCheckCounts, getTaxonomyMap } from '../../src/hardening/taxonomy';

/**
 * Guards the single source of truth for HMA's check/category counts.
 *
 * Regression context: `secure` scan output hardcoded `HMA_STATIC_CHECK_COUNT = 209`
 * (and README/docs said 209/44 and 187/39) while `--help` and `check-metadata`
 * derived 323/74 from the taxonomy — a self-contradiction a user running the CLI
 * could see. getCheckCounts() is now the one source every surface reads.
 *
 * The source-scan test below FAILS on the pre-fix code (which contained the
 * hardcoded literal), which is what gives this suite teeth.
 */
describe('check-count single source of truth', () => {
  const counts = getCheckCounts();

  it('total equals the taxonomy map size', () => {
    expect(counts.total).toBe(Object.keys(getTaxonomyMap()).length);
  });

  it('static + semantic partition the total exactly', () => {
    expect(counts.static + counts.semantic).toBe(counts.total);
  });

  it('static categories are a subset of total categories', () => {
    expect(counts.staticCategories).toBeLessThanOrEqual(counts.totalCategories);
    expect(counts.staticCategories).toBeGreaterThan(0);
  });

  // Golden values. Update these together with README.md and docs/SECURITY_CHECKS.md
  // whenever the taxonomy changes — this test fails on drift by design, forcing
  // the public-facing numbers to be updated in the same change.
  it('matches the published golden counts (update docs when this changes)', () => {
    // Raised from 324/311/13/75/70: the 24 semantic (AST) and 6 SOUL
    // narrative ids the scanner emitted without inventory entries are
    // TAXONOMY_MAP keys now, as are the 8 SEM-MCP structural checks
    // (354/37/87 → 362/45/88), which are emitted as `id:` rather than
    // `checkId:` and so were missed by a literal-only census.
    expect(counts.total).toBe(362);
    expect(counts.static).toBe(317);
    expect(counts.semantic).toBe(45);
    expect(counts.totalCategories).toBe(88);
    expect(counts.staticCategories).toBe(73);
  });

  it('the scan display no longer hardcodes a static-check count (teeth)', () => {
    const cliSource = readFileSync(join(__dirname, '../../src/cli.ts'), 'utf8');
    // The pre-fix bug: `const HMA_STATIC_CHECK_COUNT = 209;`. Any hardcoded
    // static-count literal reintroduces the drift this suite exists to prevent.
    expect(cliSource).not.toMatch(/HMA_STATIC_CHECK_COUNT\s*=\s*\d+/);
    // And the display must derive from the single source.
    expect(cliSource).toMatch(/getCheckCounts\(\)\.static/);
  });
});
