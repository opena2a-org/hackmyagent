import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'fs';
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
    //
    // 363 → 365, and one new category: TEXT-001 and TEXT-002, the two rules
    // `scan-text` emits over a free text. They are static, they are the whole
    // of the new `text` category, and they are inventory keys rather than
    // declared exclusions because they are stable rules — which is what makes
    // `check-metadata` list them and `explain <id>` answer for them.
    //
    // 365/320/89/74 → 362/317/86/71 (#395): CODEINJ-001, TMPPATH-001 and
    // ENVLEAK-001 were counted with no caller, duplicates of NEMO-005, -006
    // and -007, and are deleted. Each was the only id in its prefix, so the
    // three `codeinj`, `tmppath` and `envleak` categories go with them.
    expect(counts.total).toBe(362);
    expect(counts.static).toBe(317);
    expect(counts.semantic).toBe(45);
    expect(counts.totalCategories).toBe(86);
    expect(counts.staticCategories).toBe(71);
  });

  // #482: the golden values above are pinned to the taxonomy, but the README
  // and docs/SECURITY_CHECKS.md were only asked to follow them, and the README
  // explained its semantic figure against the scan `Checks` line but not
  // against `check-metadata`. Two numbers, two sources: the README's 29 is the
  // distinct check ids the seven analyzers emit (the published definition),
  // `check-metadata`'s semanticChecks is every AST-/SEM- taxonomy id. Hold each
  // published sentence to the source it names.
  it('README and docs/SECURITY_CHECKS.md state the counts their sources produce', () => {
    const root = join(__dirname, '../..');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const checksDoc = readFileSync(join(root, 'docs/SECURITY_CHECKS.md'), 'utf8');
    const figures = (text: string, pattern: RegExp): number[] => {
      const m = pattern.exec(text);
      expect(m, `expected ${pattern} to match`).not.toBeNull();
      return m!.slice(1).map(Number);
    };

    const analyzerDir = join(root, 'src/nanomind-core/analyzers');
    const emitted = new Set<string>();
    for (const file of readdirSync(analyzerDir).filter(f => f.endsWith('-analyzer.ts'))) {
      for (const m of readFileSync(join(analyzerDir, file), 'utf8').matchAll(/checkId:\s*['"`]([A-Z][A-Z0-9-]*-\d+)['"`]/g)) {
        emitted.add(m[1]);
      }
    }
    const ids = Object.keys(getTaxonomyMap());
    const sem = ids.filter(id => id.startsWith('SEM-'));
    const sharedWithStatic = [...emitted].filter(id => !id.startsWith('AST-'));

    expect(figures(readme, /\*\*(\d+) static checks across (\d+) categories\*\* \((\d+) checks across (\d+) categories including the NanoMind semantic layer\)/))
      .toEqual([counts.static, counts.staticCategories, counts.total, counts.totalCategories]);
    expect(figures(readme, /\*\*(\d+) NanoMind semantic checks\.\*\*/)).toEqual([emitted.size]);
    expect(figures(readme, /\(This (\d+) is the fixed catalog of check ids the seven analyzers emit\./)).toEqual([emitted.size]);
    expect(figures(readme, /reports `semanticChecks: (\d+)`/)).toEqual([counts.semantic]);
    expect(figures(readme, /the structural layer's (\d+) `SEM-` checks/)).toEqual([sem.length]);
    expect(figures(readme, /leaves out the (\d+) `UNICODE-STEGO` ids/)).toEqual([sharedWithStatic.length]);
    expect(sharedWithStatic.every(id => id.startsWith('UNICODE-STEGO-') && ids.includes(id))).toBe(true);
    expect(emitted.size - sharedWithStatic.length + sem.length).toBe(counts.semantic);

    expect(figures(checksDoc, /performs (\d+) security checks across (\d+) categories \((\d+) static checks/))
      .toEqual([counts.total, counts.totalCategories, counts.static]);
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
