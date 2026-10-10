import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';
import * as taxonomy from '../../src/hardening/taxonomy';

/**
 * docs/attack-family-census.md lists every attack family code in the three
 * registers that hold one (TAXONOMY_MAP here, the threat matrix, the OpenA2A
 * Registry), the canonical class it belongs to, and what happens to it where
 * the registers disagree. Its Matrix and Registry columns are measurements at
 * the commits it names. Everything it says about this repository is held to
 * the code here, so the census cannot drift from FAMILY_CLASS, FAMILY_FOLDS,
 * TAXONOMY_MAP or the family strings that source files set inline.
 */

const REPO_ROOT = path.join(__dirname, '..', '..');
const CENSUS_PATH = path.join(REPO_ROOT, 'docs', 'attack-family-census.md');

interface Row {
  code: string;
  cls: string;
  checks: string[];
  disposition: string;
}

/** The body under a heading, up to the next heading of the same or a higher level. */
function section(text: string, heading: string): string {
  const lines = text.split('\n');
  const start = lines.indexOf(heading);
  expect(start, `census has the heading "${heading}"`).toBeGreaterThanOrEqual(0);
  const level = heading.indexOf(' ');
  const end = lines.findIndex(
    (line, i) => i > start && /^#+ /.test(line) && line.indexOf(' ') <= level,
  );
  return lines.slice(start + 1, end === -1 ? undefined : end).join('\n');
}

/** `CRED-001..004, MCP-SSE` -> CRED-001, CRED-002, CRED-003, CRED-004, MCP-SSE. */
function expandChecks(cell: string): string[] {
  if (cell === 'absent') return [];
  return cell.split(', ').flatMap((token) => {
    const run = /^(.*)-(\d+)\.\.(\d+)$/.exec(token);
    if (!run) return [token];
    const [, prefix, from, to] = run;
    const out: string[] = [];
    for (let n = Number(from); n <= Number(to); n++) {
      out.push(`${prefix}-${String(n).padStart(from.length, '0')}`);
    }
    return out;
  });
}

function loadCensus(): { rows: Row[]; inline: Map<string, string[]> } {
  const text = readFileSync(CENSUS_PATH, 'utf8');
  const rows: Row[] = [];
  const rowRe = /^\| `([A-Z0-9-]+)` \| `([a-z_]+)` \| (.+?) \| (.+?) \| (.+?) \| (.+?) \|$/;
  for (const line of section(text, '## Census').split('\n')) {
    const m = rowRe.exec(line);
    if (m) rows.push({ code: m[1], cls: m[2], checks: expandChecks(m[3]), disposition: m[6] });
  }
  const inline = new Map<string, string[]>();
  const inlineRe = /^\| `([A-Z0-9-]+)` \| (`.+`) \|$/;
  for (const line of section(text, '### Family strings set inline outside every register').split('\n')) {
    const m = inlineRe.exec(line);
    if (m) inline.set(m[1], m[2].split(', ').map((f) => f.replace(/`/g, '')).sort());
  }
  return { rows, inline };
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** The family a fold or merge row names as its target, or undefined for a kept family. */
function targetOf(row: Row): string | undefined {
  const m = /^(?:fold|merge) into ([A-Z0-9-]+)$/.exec(row.disposition);
  return m ? m[1] : undefined;
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== '__tests__') out.push(...sourceFiles(p));
    } else if (name.endsWith('.ts') && !name.endsWith('.test.ts')) {
      out.push(p);
    }
  }
  return out;
}

describe('docs/attack-family-census.md agrees with the taxonomy', () => {
  it('lists each code once', () => {
    const { rows } = loadCensus();
    expect(rows.length).toBeGreaterThan(0);
    const seen = new Set<string>();
    const repeated = rows.map((r) => r.code).filter((c) => (seen.has(c) ? true : (seen.add(c), false)));
    expect(repeated).toEqual([]);
  });

  it('has a row for every family TAXONOMY_MAP assigns, every FAMILY_CLASS family and every fold alias', () => {
    const codes = new Set(loadCensus().rows.map((r) => r.code));
    const needed = new Set([
      ...Object.values(taxonomy.getTaxonomyMap()),
      ...Object.keys(taxonomy.FAMILY_CLASS),
      ...Object.keys(taxonomy.FAMILY_FOLDS),
    ]);
    expect([...needed].filter((c) => !codes.has(c)).sort()).toEqual([]);
  });

  it('every row is a FAMILY_CLASS family, a fold alias, or a spelling merged into a family', () => {
    const stray = loadCensus()
      .rows.filter((r) => !hasOwn(taxonomy.FAMILY_CLASS, r.code) && !hasOwn(taxonomy.FAMILY_FOLDS, r.code))
      .filter((r) => !(r.disposition.startsWith('merge into ') && hasOwn(taxonomy.FAMILY_CLASS, targetOf(r) ?? '')))
      .map((r) => r.code);
    expect(stray).toEqual([]);
  });

  it('states for each row the class getCanonicalClass returns', () => {
    const wrong = loadCensus()
      .rows.map((r) => {
        const family = r.disposition.startsWith('merge into ') ? (targetOf(r) as string) : r.code;
        return { code: r.code, census: r.cls, taxonomy: taxonomy.getCanonicalClass(family) };
      })
      .filter((r) => r.census !== r.taxonomy);
    expect(wrong).toEqual([]);
  });

  it('fold rows are exactly FAMILY_FOLDS, and merged spellings are no longer families', () => {
    const { rows } = loadCensus();
    const folds = Object.fromEntries(
      rows.filter((r) => r.disposition.startsWith('fold into ')).map((r) => [r.code, targetOf(r)]),
    );
    expect(folds).toEqual({ ...taxonomy.FAMILY_FOLDS });
    const assigned = new Set(Object.values(taxonomy.getTaxonomyMap()));
    for (const row of rows.filter((r) => r.disposition.startsWith('merge into '))) {
      expect(hasOwn(taxonomy.FAMILY_CLASS, row.code), `${row.code} is not a family`).toBe(false);
      expect(assigned.has(row.code), `TAXONOMY_MAP assigns no check to ${row.code}`).toBe(false);
    }
  });

  it('every check id a row lists maps to that code, or to the family it folds or merges into', () => {
    const map = taxonomy.getTaxonomyMap();
    const wrong: string[] = [];
    for (const row of loadCensus().rows) {
      const allowed = new Set([row.code, targetOf(row)].filter(Boolean));
      for (const checkId of row.checks) {
        if (!allowed.has(map[checkId])) wrong.push(`${checkId}: census ${row.code}, TAXONOMY_MAP ${map[checkId]}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it('every family string a source file sets inline is a row, or is listed with the files that set it', () => {
    const { rows, inline } = loadCensus();
    const codes = new Set(rows.map((r) => r.code));
    const measured = new Map<string, Set<string>>();
    const literal = /attackClass:\s*'([A-Z][A-Z0-9-]*)'/g;
    for (const file of sourceFiles(path.join(REPO_ROOT, 'src'))) {
      const rel = path.relative(REPO_ROOT, file).split(path.sep).join('/');
      for (const m of readFileSync(file, 'utf8').matchAll(literal)) {
        if (codes.has(m[1])) continue;
        if (!measured.has(m[1])) measured.set(m[1], new Set());
        measured.get(m[1])!.add(rel);
      }
    }
    const asListed = Object.fromEntries([...inline].sort(([a], [b]) => a.localeCompare(b)));
    const asSet = Object.fromEntries(
      [...measured].sort(([a], [b]) => a.localeCompare(b)).map(([s, files]) => [s, [...files].sort()]),
    );
    expect(asListed).toEqual(asSet);
    // None of them has a class: the normalisation refuses each one.
    for (const family of inline.keys()) {
      expect(() => taxonomy.getCanonicalClass(family)).toThrow(`unknown attack family: ${family}`);
    }
  });
});
