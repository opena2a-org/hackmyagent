/**
 * #995 — src/nanomind-core/README.md described analyzers that no longer
 * matched the code: the capability row listed AST-GOVERN (which only appears
 * in a comment since governance-analyzer took over constraint weakness), the
 * scope row stopped at AST-SCOPE-003 while the analyzer emits AST-SCOPE-004,
 * the stego analyzer had no row at all, and the Tests section claimed "172
 * tests across 7 test files" against 80 files on disk.
 *
 * This suite holds the analyzer table to the check ids each analyzer source
 * actually emits, and holds any test-file count the README states to the
 * directory it names.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');
const CORE_DIR = path.join(REPO_ROOT, 'src', 'nanomind-core');
const ANALYZERS_DIR = path.join(CORE_DIR, 'analyzers');
const README = readFileSync(path.join(CORE_DIR, 'README.md'), 'utf-8');

/** `| \`file.ts\` | checks | description |` rows of the Analyzers table. */
function analyzerRows(src: string): Map<string, string> {
  const section = src.split(/^### Analyzers/m)[1]?.split(/^#{2,3} /m)[0] ?? '';
  const rows = new Map<string, string>();
  for (const m of section.matchAll(/^\|\s*`([\w-]+\.ts)`\s*\|([^|]*)\|/gm)) {
    rows.set(m[1], m[2].trim());
  }
  return rows;
}

/** Expands "AST-CAP-001 to 002, AST-EXFIL-001" into the ids it names. */
function expandChecks(cell: string): Set<string> {
  const ids = new Set<string>();
  for (const item of cell.split(',').map(s => s.trim()).filter(Boolean)) {
    const range = item.match(/^([A-Z][A-Z-]*)-(\d{3}) to (\d{3})$/);
    if (range) {
      const [, prefix, from, to] = range;
      for (let n = Number(from); n <= Number(to); n++) {
        ids.add(`${prefix}-${String(n).padStart(3, '0')}`);
      }
      continue;
    }
    const single = item.match(/^[A-Z][A-Z-]*-\d{3}$/);
    if (!single) throw new Error(`unparseable check id entry in README table: "${item}"`);
    ids.add(item);
  }
  return ids;
}

/** Every `checkId: '<ID>'` literal an analyzer source emits. */
function emittedIds(file: string): Set<string> {
  const src = readFileSync(path.join(ANALYZERS_DIR, file), 'utf-8');
  const ids = new Set<string>();
  for (const m of src.matchAll(/checkId:\s*['"`]([A-Z][A-Z-]*-\d{3})['"`]/g)) ids.add(m[1]);
  return ids;
}

const sorted = (s: Set<string>) => [...s].sort();

describe('nanomind-core README analyzer table (#995)', () => {
  const rows = analyzerRows(README);
  const emitting = readdirSync(ANALYZERS_DIR)
    .filter(f => f.endsWith('.ts'))
    .filter(f => emittedIds(f).size > 0)
    .sort();

  it('has a row for every analyzer that emits a check id', () => {
    expect(emitting.length).toBeGreaterThan(0);
    expect([...rows.keys()].sort()).toEqual(emitting);
  });

  it.each(emitting)('%s row lists exactly the check ids the source emits', file => {
    const cell = rows.get(file);
    expect(cell, `no README row for ${file}`).toBeDefined();
    expect(sorted(expandChecks(cell!))).toEqual(sorted(emittedIds(file)));
  });

  it('parses ranges and single ids', () => {
    expect(sorted(expandChecks('AST-CAP-001 to 002, AST-EXFIL-001'))).toEqual([
      'AST-CAP-001',
      'AST-CAP-002',
      'AST-EXFIL-001',
    ]);
    expect(() => expandChecks('AST-GOVERN')).toThrow(/unparseable/);
  });
});

describe('nanomind-core README test counts (#995)', () => {
  function testFiles(dir: string): number {
    let n = 0;
    for (const name of readdirSync(dir)) {
      const p = path.join(dir, name);
      if (statSync(p).isDirectory()) n += testFiles(p);
      else if (name.endsWith('.test.ts')) n++;
    }
    return n;
  }

  it('states no test-file count that differs from __tests__/nanomind-core', () => {
    const actual = testFiles(path.join(REPO_ROOT, '__tests__', 'nanomind-core'));
    for (const m of README.matchAll(/(\d+)\s+test files/g)) {
      expect(Number(m[1])).toBe(actual);
    }
  });

  it('states no total test count, which only a full run can measure', () => {
    expect(README).not.toMatch(/\b\d+\s+tests\b/);
  });
});
