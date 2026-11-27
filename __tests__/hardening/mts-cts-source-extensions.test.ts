/**
 * `secure` read no `.mts` or `.cts` file, so a finding in one was never
 * reported. The TypeScript module variants were missing from
 * `JS_FAMILY_EXTENSIONS`, from the source-file set and from the stego walk,
 * and the 27 source checks (LOG-002, AUTH-003 to AUDIT-004) admitted files
 * through 56 hand-written `endsWith('.ts') || endsWith('.js')` filters.
 *
 * The contract is that the extension is not a gate between the variants: the
 * same bytes under `.ts`, `.mts` and `.cts` give the same findings, and the
 * coverage ledger counts the file as read under each. The fixture is walked
 * under every extension; `.ts` is the baseline the others must equal, and a
 * `.bin` copy is the negative control that proves extension gating still
 * happens at all.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner, isJsFamilyFile } from '../../src/hardening/scanner';
import type { ScanResult } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

const PACKAGE = '{"name":"probe","version":"1.0.0"}\n';

// One file that trips a tree-wide source check (LOG-002) and the stego walk
// (UNICODE-STEGO-001, via a zero-width space assembled here so this test file
// carries none itself), beside a shell-out for the checks that read one.
const ZWSP = String.fromCodePoint(0x200b);
const HAZARD =
  "import { exec } from 'node:child_process';\n" +
  'export function login(password: string): void { console.log(password); }\n' +
  'export function list(dir: string): void { exec(`ls ${dir}`); }\n' +
  `export const marker = 'a${ZWSP}b';\n`;

const EXTENSIONS = ['.ts', '.mts', '.cts'] as const;

function projectWith(ext: string): string {
  const dir = tempDir('hma-mts-cts-');
  fs.writeFileSync(path.join(dir, 'package.json'), PACKAGE);
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', `app${ext}`), HAZARD);
  return dir;
}

function scan(dir: string): Promise<ScanResult> {
  return new HardeningScanner().scan({ targetDir: dir });
}

/** Every record, with the fixture's own extension rewritten to `.ts` so runs compare. */
function normalized(result: ScanResult, ext: string): unknown {
  const records = JSON.stringify(result.allFindings ?? []);
  return JSON.parse(records.split(`app${ext}`).join('app.ts'));
}

function failing(result: ScanResult, checkId: string) {
  return (result.allFindings ?? []).find((f) => f.checkId === checkId && f.passed === false);
}

describe('.mts and .cts are read like .ts', () => {
  it('admits every TypeScript and JavaScript variant through the shared test, and nothing else', () => {
    for (const name of ['a.ts', 'a.mts', 'a.cts', 'a.js', 'a.mjs', 'a.cjs', 'a.tsx', 'a.jsx', 'A.MTS', 'src/a.cts']) {
      expect(isJsFamilyFile(name), name).toBe(true);
    }
    for (const name of ['a.json', 'a.md', 'a.bin', 'a.sh', 'a.py', 'mts', 'a.ts.bak']) {
      expect(isJsFamilyFile(name), name).toBe(false);
    }
  });

  it('gives the same findings and counts the file as read under .ts, .mts and .cts', async () => {
    const empty = await scan(projectWith('.bin'));
    const runs = await Promise.all(EXTENSIONS.map(async (ext) => ({ ext, result: await scan(projectWith(ext)) })));
    const baseline = runs[0].result;

    // The premise: the .ts baseline is reported by a source check and by the
    // stego walk. Without it the comparison proves nothing.
    expect(failing(baseline, 'LOG-002')).toMatchObject({ file: path.join('src', 'app.ts') });
    expect(failing(baseline, 'UNICODE-STEGO-001')).toMatchObject({ file: path.join('src', 'app.ts') });

    // The negative control: the same bytes behind an extension no walk reads.
    expect(failing(empty, 'LOG-002')).toBeUndefined();
    expect(failing(empty, 'UNICODE-STEGO-001')).toBeUndefined();
    expect(baseline.coverage?.filesExamined ?? 0).toBeGreaterThan(empty.coverage?.filesExamined ?? 0);

    for (const { ext, result } of runs.slice(1)) {
      const file = path.join('src', `app${ext}`);
      expect(failing(result, 'LOG-002'), `LOG-002 under ${ext}`).toMatchObject({ file });
      expect(failing(result, 'UNICODE-STEGO-001'), `UNICODE-STEGO-001 under ${ext}`).toMatchObject({ file });
      expect(normalized(result, ext), `findings under ${ext} differ from .ts`).toEqual(normalized(baseline, '.ts'));
      expect(result.coverage?.filesExamined, `coverage.filesExamined under ${ext}`).toBe(baseline.coverage?.filesExamined);
    }
  });

  it('admits every name the earlier endsWith filter admitted, whatever the stem', () => {
    const old = (name: string): boolean => name.endsWith('.ts') || name.endsWith('.js');
    const stems = ['', 'a', 'a.b.c', '.', '..', 'a.d', 'src/', 'src/a', 'src/a.b', 'src/.', 'src/a/b/'];
    const extensions = ['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts', '.d.ts', '.tsx', '.jsx'];
    for (const stem of stems) {
      for (const ext of extensions) {
        const name = `${stem}${ext}`;
        if (old(name)) expect(isJsFamilyFile(name), name).toBe(true);
        if (['.mjs', '.cjs', '.mts', '.cts'].includes(ext)) expect(isJsFamilyFile(name), name).toBe(true);
      }
    }
    for (const name of ['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts']) {
      expect(isJsFamilyFile(name), name).toBe(true);
    }
  });

  it('reads a top-level file whose whole name is .js', async () => {
    const dir = tempDir('hma-dot-js-');
    fs.writeFileSync(path.join(dir, 'package.json'), PACKAGE);
    fs.writeFileSync(path.join(dir, '.js'), HAZARD);
    const result = await scan(dir);
    expect(failing(result, 'LOG-002')).toMatchObject({ file: '.js' });
  });
});
