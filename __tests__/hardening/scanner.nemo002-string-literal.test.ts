import { describe, it, expect } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import { HardeningScanner, hasDigestSkipInCode } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

/**
 * NEMO-002 flags code that skips digest verification when the digest is
 * falsy. It matched the same shape written as prose inside string and
 * template literals — a taxonomy that describes the check reported itself
 * as a CRITICAL bypass. The pattern now counts only when it occurs as code.
 */

async function nemo002(root: string): Promise<Array<[string, number]>> {
  const drafts: any[] = await (new HardeningScanner() as any).checkNemoClawPatterns(root, false);
  return drafts
    .filter((f) => f.checkId === 'NEMO-002' && !f.passed)
    .map((f) => [f.file, f.line]);
}

const TAXONOMY = [
  'export const TAXONOMY = [',
  '  {',
  "    id: 'digest-skip',",
  "    example: 'if (!artifact.digest) return; // verification skipped',",
  '    detail: "if (manifest.digest && verify(manifest)) only checks present digests",',
  '    note: `if (!digest) { skip() }`,',
  '    long: `',
  '      Code like if (!entry.digest) continue; lets a stripped manifest through,',
  '      and if (entry.digest && check(entry)) does the same.',
  '    `,',
  '  },',
  '];',
  '',
].join('\n');

const REAL = [
  'export function install(artifact) {',
  '  if (!artifact.digest) return fetchUnverified(artifact);',
  '  if (artifact.digest && verify(artifact)) return artifact;',
  '}',
  '',
].join('\n');

describe('NEMO-002 digest skip as code, not prose in string literals', () => {
  it('reports nothing for taxonomy.mjs with the pattern only in string and template literals', async () => {
    const root = tempDir('nemo002-taxonomy-');
    await fs.writeFile(path.join(root, 'taxonomy.mjs'), TAXONOMY);
    expect(await nemo002(root)).toEqual([]);
  });

  it('still reports real code that skips verification on a falsy digest', async () => {
    const root = tempDir('nemo002-real-');
    await fs.writeFile(path.join(root, 'install.mjs'), REAL);
    expect(await nemo002(root)).toEqual([
      ['install.mjs', 2],
      ['install.mjs', 3],
    ]);
  });

  it('judges each end of the pattern on its own line position', () => {
    expect(hasDigestSkipInCode("const s = 'if (!digest) skip';")).toBe(false);
    expect(hasDigestSkipInCode('if (x) log("no digest && y");')).toBe(false);
    expect(hasDigestSkipInCode("if (!load('m.json').digest) return;")).toBe(true);
    expect(hasDigestSkipInCode("log('if (!digest)'); if (!m.digest) return;")).toBe(true);
    expect(hasDigestSkipInCode('if (m.digest) verify(m);')).toBe(false);
    expect(hasDigestSkipInCode('// if (!digest) return;')).toBe(false);
  });
});
