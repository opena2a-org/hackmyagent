/**
 * The reverse of the check-id census (#970): every counted check has an
 * emitter some command reaches.
 *
 * checkid-census.test.ts holds every emitted id to the inventory. This file
 * holds the inventory to the emitters. Before it, `secure --help` advertised
 * 362 checks and README "317 static checks across 71 categories" while 56 of
 * the counted ids could not be reported by any command: PARSE-001..010,
 * FAKETOOL-001..010, PERSIST-004..010 and ASKILL-002 had no emitter at all,
 * and the 28 HMA-NMC ids were emitted only by NemoClawScanner, a class no
 * command constructs. Those ids stay TAXONOMY_MAP keys (attack-family
 * mappings) and are declared in getNotCountedCheckIds(), which every count
 * subtracts.
 *
 * "Reached by a command" is measured in two steps. The emitting files are the
 * import closure of src/cli.ts, the one bin entry. Import reach is not enough
 * on its own: nemoclaw-scanner.ts is in that closure through the
 * hardening/index.ts re-export while nothing constructs its class. So a file
 * that declares a not-wired emitter class is left out of the population, and
 * a separate cell fails the moment any source file constructs that class.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import {
  getCheckCounts,
  getCountedCheckIds,
  getNotCountedCheckIds,
  getTaxonomyMap,
} from '../../src/hardening/taxonomy';

const SRC_ROOT = resolve(__dirname, '../../src');
const ENTRY = join(SRC_ROOT, 'cli.ts');
// Holds the inventory keys themselves, never an emission site.
const TAXONOMY_FILE = join(SRC_ROOT, 'hardening/taxonomy.ts');

const IMPORT_RE = /(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g;
// The emission shapes the forward census reads: `checkId:` and `id:` string
// literals (SemanticFinding ids, the scanner's pattern arrays, the scan-soul
// control catalogue), plus the exported `*_CHECK_ID` constants of scan-text.
const EMISSION_RES = [
  /\b(?:checkId|id):\s*['"`]([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)['"`]/g,
  /\bexport const [A-Z_]+_CHECK_ID = '([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)'/g,
];

function isTestFile(file: string): boolean {
  return file.includes('/__tests__/') || /\.test\.ts$/.test(file);
}

function resolveImport(fromFile: string, spec: string): string | null {
  const base = resolve(dirname(fromFile), spec).replace(/\.js$/, '');
  for (const candidate of [`${base}.ts`, join(base, 'index.ts')]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  return null;
}

/** Every non-test src file reachable from `entry` through relative imports. */
function importClosure(entry: string): Set<string> {
  const seen = new Set<string>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const m of readFileSync(file, 'utf8').matchAll(IMPORT_RE)) {
      const target = resolveImport(file, m[1]);
      if (target && !isTestFile(target)) pending.push(target);
    }
  }
  return seen;
}

function walkTs(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules') continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walkTs(p));
    else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts') && !isTestFile(p)) out.push(p);
  }
  return out;
}

function emittedIds(text: string): Set<string> {
  const ids = new Set<string>();
  for (const re of EMISSION_RES) for (const m of text.matchAll(re)) ids.add(m[1]);
  return ids;
}

/**
 * Every quoted id-shaped literal, whatever carries it. NemoClawScanner passes
 * its ids to helpers (`finding('HMA-NMC-011', …)`), a shape the emission
 * patterns above do not read; the issue's own verify command reads this way.
 */
function quotedIds(text: string): Set<string> {
  return new Set([...text.matchAll(/['"`]([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)['"`]/g)].map((m) => m[1]));
}

/** Source files that construct `className`, other than the file declaring it. */
function constructionSites(
  className: string,
  sources: ReadonlyMap<string, string>,
  declaringFile: string,
): string[] {
  const re = new RegExp(`\\bnew\\s+${className}\\s*\\(`);
  return [...sources.entries()]
    .filter(([file, text]) => file !== declaringFile && re.test(text))
    .map(([file]) => relative(SRC_ROOT, file))
    .sort();
}

const sources = new Map(walkTs(SRC_ROOT).map((f) => [f, readFileSync(f, 'utf8')] as const));
const reachable = importClosure(ENTRY);
const notCounted = getNotCountedCheckIds();
const notWired = notCounted.filter((e) => e.notWiredEmitter);

/** The file declaring each not-wired emitter class. */
const declaringFileOf = new Map<string, string>();
for (const entry of notWired) {
  const cls = entry.notWiredEmitter!;
  const files = [...sources.entries()]
    .filter(([, text]) => new RegExp(`\\bexport class ${cls}\\b`).test(text))
    .map(([file]) => file);
  if (files.length === 1) declaringFileOf.set(cls, files[0]);
}

/** Ids emitted by reachable files, leaving out the given files. */
function reachablePopulation(leaveOut: ReadonlySet<string>): Set<string> {
  const ids = new Set<string>();
  for (const file of reachable) {
    if (file === TAXONOMY_FILE || leaveOut.has(file)) continue;
    for (const id of emittedIds(sources.get(file) ?? readFileSync(file, 'utf8'))) ids.add(id);
  }
  return ids;
}

const notWiredFiles = new Set(declaringFileOf.values());
const population = reachablePopulation(notWiredFiles);

/** Counted ids with no emitter in the population. */
function countedGap(counted: readonly string[], emitted: ReadonlySet<string>): string[] {
  return counted.filter((id) => !emitted.has(id)).sort();
}

describe('every counted check has an emitter a command reaches (#970)', () => {
  it('the closure and the population measure the real emitters (non-vacuity floor)', () => {
    expect(reachable.size).toBeGreaterThan(100);
    for (const file of ['hardening/scanner.ts', 'scanner/external-scanner.ts', 'hardening/text-payload-scan.ts']) {
      expect(reachable.has(join(SRC_ROOT, file)), `${file} must be in the closure of cli.ts`).toBe(true);
    }
    for (const id of ['CRED-001', 'AST-CRED-001', 'SEM-MCP-001', 'TEXT-001', 'API-KEY-EXPOSED', 'SOUL-CONTRADICTION']) {
      expect(population.has(id), `${id} must be read as emitted`).toBe(true);
    }
  });

  it('every counted id is emitted by a file the cli reaches', () => {
    const gap = countedGap(getCountedCheckIds(), population);
    expect(
      gap,
      `${gap.length} counted id(s) have no emitter any command reaches. Implement the ` +
        'detector, or declare the ids in NOT_COUNTED in src/hardening/taxonomy.ts with the reason.',
    ).toEqual([]);
  });

  it('plant: a counted id with no emitter is reported as exactly that id', () => {
    expect(countedGap([...getCountedCheckIds(), 'PARSE-001'], population)).toEqual(['PARSE-001']);
  });

  it('every count is taken over the counted ids', () => {
    const counts = getCheckCounts();
    const inventory = Object.keys(getTaxonomyMap());
    const declared = notCounted.flatMap((e) => e.ids);
    expect(new Set(declared).size, 'a not-counted id is declared twice').toBe(declared.length);
    expect(declared.filter((id) => !inventory.includes(id)), 'not-counted ids must be inventory keys').toEqual([]);
    expect(counts.total).toBe(getCountedCheckIds().length);
    expect(counts.total).toBe(inventory.length - declared.length);
  });

  it('a not-counted id without a not-wired emitter is quoted nowhere in src but the taxonomy', () => {
    const everywhere = new Set<string>();
    for (const [file, text] of sources) {
      if (file !== TAXONOMY_FILE) for (const id of quotedIds(text)) everywhere.add(id);
    }
    const emittedNow = notCounted
      .filter((e) => !e.notWiredEmitter)
      .flatMap((e) => e.ids)
      .filter((id) => everywhere.has(id));
    expect(
      emittedNow,
      'these ids are written in src now: if a detector emits them, remove them from NOT_COUNTED ' +
        'so the counts include them',
    ).toEqual([]);
    // The declaration names the ids the issue measured, family by family.
    const byFamily = Object.fromEntries(notCounted.map((e) => [e.family, e.ids.length]));
    expect(byFamily).toEqual({ ASKILL: 1, FAKETOOL: 10, 'HMA-NMC': 28, PARSE: 10, PERSIST: 7 });
  });

  it('a not-wired emitter class is declared once, emits its ids, and nothing constructs it', () => {
    expect(notWired.map((e) => e.notWiredEmitter)).toEqual(['NemoClawScanner']);
    for (const entry of notWired) {
      const cls = entry.notWiredEmitter!;
      const file = declaringFileOf.get(cls);
      expect(file, `exactly one src file must declare class ${cls}`).toBeDefined();
      expect(entry.ids.length).toBeGreaterThan(0);
      const fromClass = quotedIds(sources.get(file!)!);
      expect(entry.ids.filter((id) => !fromClass.has(id)), `${cls} must emit every id declared for it`).toEqual([]);
      expect(
        constructionSites(cls, sources, file!),
        `${cls} is constructed now: remove its NOT_COUNTED entry in src/hardening/taxonomy.ts so its ids are counted`,
      ).toEqual([]);
    }
  });

  it('plant: a source that constructs the not-wired class is reported', () => {
    const file = declaringFileOf.get('NemoClawScanner')!;
    const planted = new Map(sources);
    planted.set(ENTRY, `${sources.get(ENTRY)}\nconst s = new NemoClawScanner();\n`);
    expect(constructionSites('NemoClawScanner', planted, file)).toEqual(['cli.ts']);
  });

  it('import reach alone would not settle the not-wired ids, which is why the class is guarded', () => {
    // nemoclaw-scanner.ts is in the closure of cli.ts (hardening/index.ts
    // re-exports the class), so a reach-only census would read its
    // `checkId:` sites as reachable emitters.
    const file = declaringFileOf.get('NemoClawScanner')!;
    expect(reachable.has(file), 'the not-wired class file is import-reachable from cli.ts').toBe(true);
    const byImportOnly = reachablePopulation(new Set());
    const hmaNmc = notWired[0].ids;
    expect(hmaNmc.some((id) => byImportOnly.has(id))).toBe(true);
    expect(hmaNmc.filter((id) => population.has(id))).toEqual([]);
  });
});
