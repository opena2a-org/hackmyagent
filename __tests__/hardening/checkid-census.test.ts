/**
 * HMA-29 — the check inventory covers (or names its exclusions of) every id
 * the scanner emits, and the gap cannot regrow silently.
 *
 * Measured baseline at the grounding snapshot (d6fade15 / cebbc442):
 * TAXONOMY_MAP carried 324 keys while 50 distinct `checkId:` literals in
 * src/ were absent from it — AST 24 (including AST-CRED-001), CHK 11,
 * SOUL 6, FIX 4, SCAN 4, SEM 1. `check-metadata` advertised "totalChecks
 * 324" as if that were the whole story.
 *
 * AC3: every emitted id is now an inventory key, or the CLI's
 *      `check-metadata` output carries an explicit exclusions declaration
 *      naming the family and the reason (TAXONOMY_EXEMPT_CHECKIDS made
 *      visible, plus the CHK test-fixture family).
 * AC4: this census extracts the emitted `checkId:` literals from src/ —
 *      the SAME population the baseline measured, in-src test fixtures
 *      included, which is why the walk does NOT skip `__tests__`
 *      directories the way taxonomy-coverage.test.ts (#138) does — and
 *      fails when any emitted id is neither an inventory key nor
 *      declared-excluded. The plant cell proves it non-vacuous.
 *
 * Relationship to taxonomy-coverage.test.ts (#138): that suite accepts an
 * inline `attackClass:` at the emission site as an alternative to a map
 * entry, which is exactly how the 24 AST and 6 SOUL ids stayed invisible
 * to `check-metadata` — reported to users, absent from the advertised
 * inventory. This census does not accept the inline alternative.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import {
  getTaxonomyMap,
  getCheckCounts,
  getDeclaredCheckIdExclusions,
  isDeclaredExcludedCheckId,
  TAXONOMY_EXEMPT_CHECKIDS,
} from '../../src/hardening/taxonomy';

const SRC_ROOT = resolve(__dirname, '../../src');
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git']);
// The taxonomy file holds `'CRED-001': '...'` mapping keys, not emission
// sites; everything else in src/ — in-src test fixtures included — counts,
// because that is the population the HMA-29 baseline measured (273 emitted
// ids, 50 unmapped).
const SKIP_FILES = new Set([resolve(SRC_ROOT, 'hardening/taxonomy.ts')]);

const CHECKID_RE = /checkId:\s*(?:['"]([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)['"]|`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`)/g;

function walkTs(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walkTs(p));
    else if (st.isFile() && entry.endsWith('.ts') && !entry.endsWith('.d.ts') && !SKIP_FILES.has(p)) out.push(p);
  }
  return out;
}

function collectEmittedCheckIds(): Set<string> {
  const emitted = new Set<string>();
  for (const file of walkTs(SRC_ROOT)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(CHECKID_RE)) {
      emitted.add(m[1] ?? m[2]!);
    }
  }
  return emitted;
}

/**
 * The census: emitted ids that are neither inventory keys nor declared
 * excluded. Factored over its inputs so the plant cell below can hand it a
 * doctored inventory and watch it fail on exactly the planted id.
 */
function censusGap(
  emitted: ReadonlySet<string>,
  inventory: ReadonlySet<string>,
  isExcluded: (id: string) => boolean,
): string[] {
  return [...emitted].filter((id) => !inventory.has(id) && !isExcluded(id)).sort();
}

const emitted = collectEmittedCheckIds();
const inventory = new Set(Object.keys(getTaxonomyMap()));

describe('HMA-29.AC4 — emitted-checkId census', () => {
  it('HMA-29.AC4 the walk reads the emission population at all (non-vacuity floor)', () => {
    // The baseline measured 273 distinct emitted ids; a walk that returns a
    // trivial set is measuring nothing.
    expect(emitted.size).toBeGreaterThan(200);
    expect(emitted.has('AST-CRED-001')).toBe(true); // the headline gap id
    expect(emitted.has('CRED-001')).toBe(true);
  });

  it('HMA-29.AC4 every emitted checkId is an inventory key or declared-excluded', () => {
    const gap = censusGap(emitted, inventory, isDeclaredExcludedCheckId);
    expect(
      gap,
      `${gap.length} emitted id(s) are neither TAXONOMY_MAP keys nor in the ` +
        `declared exclusions (getDeclaredCheckIdExclusions). Add each to the ` +
        `inventory, or register a declared exclusion with its reason in ` +
        `src/hardening/taxonomy.ts.`,
    ).toEqual([]);
  });

  it('HMA-29.AC4 plant: an emitted id removed from the inventory in-memory is reported as exactly that id', () => {
    const doctored = new Set(inventory);
    doctored.delete('AST-CRED-001');
    expect(censusGap(emitted, doctored, isDeclaredExcludedCheckId)).toEqual(['AST-CRED-001']);
  });
});

describe('HMA-29.AC3 — the inventory covers, or declares its exclusion of, every emitted family', () => {
  const exclusions = getDeclaredCheckIdExclusions();

  // The six families the baseline found emitted-but-uninventoried, with the
  // shape each must have landed in.
  it.each([
    ['AST', 'inventory'],
    ['SOUL', 'inventory'],
    ['CHK', 'excluded'],
    ['FIX', 'excluded'],
    ['SCAN', 'excluded'],
    ['SEM', 'excluded'],
  ] as const)('HMA-29.AC3 baseline gap family %s is covered (%s)', (family, _shape) => {
    const familyEmitted = [...emitted].filter((id) => id.split('-')[0] === family);
    expect(familyEmitted.length).toBeGreaterThan(0);
    const uncovered = familyEmitted.filter(
      (id) => !inventory.has(id) && !isDeclaredExcludedCheckId(id),
    );
    expect(uncovered, `family ${family} still has uncovered emitted ids`).toEqual([]);
  });

  it('HMA-29.AC3 the 24 baseline AST ids and 6 SOUL ids are inventory keys, counted by totalChecks', () => {
    const baselineAst = [
      'AST-CAP-001', 'AST-CAP-002', 'AST-CODE-001', 'AST-CODE-002', 'AST-CODE-003',
      'AST-CRED-001', 'AST-CRED-002', 'AST-CRED-003',
      'AST-GOV-001', 'AST-GOV-002', 'AST-GOV-003', 'AST-GOV-004', 'AST-GOV-005',
      'AST-HEARTBEAT-001', 'AST-INJECT-001', 'AST-MANIP-001', 'AST-PERSIST-001',
      'AST-PROMPT-001', 'AST-PROMPT-002', 'AST-PROMPT-003', 'AST-PROMPT-004',
      'AST-SCOPE-001', 'AST-SCOPE-002', 'AST-SCOPE-003',
    ];
    const baselineSoul = [
      'SOUL-BYPASS', 'SOUL-COMPLETENESS', 'SOUL-CONSENT', 'SOUL-CONTRADICTION',
      'SOUL-ESCAPE-CLAUSE', 'SOUL-UNVERIFIABLE-CLAIM',
    ];
    for (const id of [...baselineAst, ...baselineSoul]) {
      expect(inventory.has(id), `${id} must be a TAXONOMY_MAP key`).toBe(true);
    }
    // totalChecks is derived from the map, so the additions are reflected in
    // what check-metadata advertises.
    expect(getCheckCounts().total).toBe(inventory.size);
    expect(inventory.size).toBeGreaterThanOrEqual(324 + baselineAst.length + baselineSoul.length);
  });

  it('HMA-29.AC3 every declared exclusion names a family and a reason', () => {
    expect(exclusions.length).toBeGreaterThan(0);
    for (const ex of exclusions) {
      expect(ex.family).toMatch(/^[A-Z][A-Z0-9]*$/);
      expect(ex.reason.length, `${ex.family} exclusion must say WHY`).toBeGreaterThan(20);
    }
    const families = exclusions.map((e) => e.family);
    for (const fam of ['CHK', 'FIX', 'SCAN', 'SEM']) {
      expect(families, `family ${fam} must carry a declared exclusion`).toContain(fam);
    }
  });

  it('HMA-29.AC3 the visible exclusions cover every TAXONOMY_EXEMPT_CHECKIDS member (the mechanism, made visible)', () => {
    const declaredIds = new Set(exclusions.flatMap((e) => e.ids));
    for (const id of TAXONOMY_EXEMPT_CHECKIDS) {
      expect(declaredIds.has(id), `exempt id ${id} missing from the declared exclusions`).toBe(true);
      expect(isDeclaredExcludedCheckId(id)).toBe(true);
    }
    // And the declaration is not an over-broad blanket: an ordinary security
    // check id is neither exempt nor family-excluded.
    expect(isDeclaredExcludedCheckId('CRED-001')).toBe(false);
    expect(isDeclaredExcludedCheckId('AST-CRED-001')).toBe(false);
  });
});

describe.runIf(existsSync(CLI))('HMA-29.AC3 — check-metadata carries the coverage and the exclusions (spawn)', () => {
  beforeAll(assertDistFreshIfPresent);

  it('HMA-29.AC3 check-metadata --json: totalChecks reflects the AST ids and exclusions are declared', () => {
    const res = spawnSync(process.execPath, [CLI, 'check-metadata', '--json'], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    expect(res.status).toBe(0);
    const payload = JSON.parse(res.stdout);

    expect(payload.totalChecks).toBe(getCheckCounts().total);
    expect(payload.checks['AST-CRED-001']).toBeDefined();
    expect(payload.checks['SOUL-CONTRADICTION']).toBeDefined();

    expect(Array.isArray(payload.exclusions)).toBe(true);
    const byFamily = new Map<string, { family: string; ids: string[]; reason: string }>(
      payload.exclusions.map((e: { family: string; ids: string[]; reason: string }) => [e.family, e]),
    );
    for (const fam of ['CHK', 'FIX', 'SCAN', 'SEM']) {
      const ex = byFamily.get(fam);
      expect(ex, `check-metadata must declare the ${fam} exclusion`).toBeDefined();
      expect(ex!.reason.length).toBeGreaterThan(20);
    }
    expect(byFamily.get('FIX')!.ids).toContain('FIX-SUMMARY');
    expect(byFamily.get('SEM')!.ids).toContain('SEM-LLM-NOT-ANALYZED');
  });
});
