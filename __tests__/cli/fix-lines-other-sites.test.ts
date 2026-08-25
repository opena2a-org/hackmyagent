/**
 * #596 — the sites that still printed a composed fix as one escaped line.
 *
 * #367 moved the two findings-list sites to one authored part per line. Three
 * other prints still rendered `escapeForDisplay(finding.fix)` whole, so a
 * composed fix there showed every authored newline as `\n`; a fourth renderer
 * (`displayCheckFindings`) had the same shape and no callers. This asks the
 * source: no print in `src/cli.ts` interpolates a finding's `fix` whole any
 * more, every fix print goes through the `fixParts` idiom the #367 tripwires
 * cover, and the dead renderer is gone.
 *
 * Line-based, like `error-render-idiom.test.ts`: a site that copies `f.fix`
 * into a local and prints the local on another line evades it. It is a
 * tripwire against the observed failure mode, not a taint analysis.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const src = readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
const lines = src.split('\n');

describe('#596 no whole-string fix print survives in src/cli.ts', () => {
  it('no print interpolates a finding fix whole', () => {
    const offenders = lines
      .map((l, i) => ({ l, n: i + 1 }))
      .filter(({ l }) => /console\.(log|error)\(/.test(l) && /\$\{[^}]*\b\w+\.fix\b[^}]*\}/.test(l));
    expect(offenders.map(({ n, l }) => `${n}: ${l.trim()}`)).toEqual([]);
  });

  it('every fix print reads its parts through fixParts, and every loop has its escaped print', () => {
    const partsReads = lines.filter((l) => /const parts = fixParts\(/.test(l)).length;
    const loops = lines.filter((l) => /for \(const part of parts\.slice\(1\)\)/.test(l)).length;
    // Non-vacuity: the two findings-list sites, the three converted ones, and scan-soul's.
    expect(partsReads).toBeGreaterThanOrEqual(6);
    expect(loops).toBe(partsReads);
  });

  it('the dead renderer is gone', () => {
    expect(src).not.toContain('displayCheckFindings');
  });
});
