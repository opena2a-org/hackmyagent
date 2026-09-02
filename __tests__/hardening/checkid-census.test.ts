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
 *      visible, plus family/pattern exclusions).
 * AC4: this census extracts the emitted `checkId:` literals from src/ —
 *      in-src test fixtures included, which is why the walk does NOT skip
 *      `__tests__` directories the way taxonomy-coverage.test.ts (#138)
 *      does — and fails when any emitted id is neither an inventory key
 *      nor declared-excluded. The plant cell proves it non-vacuous.
 * AC5: the r1 census read only `checkId: '<literal>'` and was blind to the
 *      other emission shapes (r1 review findings 1 and 5). It now also
 *      reads: `id: 'SEM-…'` literals under src/semantic (carried into
 *      `SecurityFinding.checkId` by finding-adapter.ts), `PREFIX-${…}`
 *      template ids (ARP-* in eval/oracle.ts, SEM-LLM-NNN in
 *      semantic/llm/index.ts, the red-team payload counters, the NanoMind
 *      daemon narrative families), and a registered list of
 *      expression-valued `checkId:` sites (ctrl.id, check.id, finding.id,
 *      r.payload.id) each resolved to its population. One plant per shape.
 *
 * Relationship to taxonomy-coverage.test.ts (#138): that suite accepts an
 * inline `attackClass:` at the emission site as an alternative to a map
 * entry, which is exactly how the 24 AST, 6 SOUL and 8 SEM-MCP ids stayed
 * invisible to `check-metadata` — reported to users, absent from the
 * advertised inventory. This census does not accept the inline alternative.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import {
  getTaxonomyMap,
  getCheckCounts,
  getCheckSeverity,
  getAttackClass,
  getDeclaredCheckIdExclusions,
  isDeclaredExcludedCheckId,
  checkIdExclusionMatches,
  TAXONOMY_EXEMPT_CHECKIDS,
  type CheckIdExclusion,
} from '../../src/hardening/taxonomy';
import { CONTROL_DEFS } from '../../src/soul/scanner';

const SRC_ROOT = resolve(__dirname, '../../src');
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git']);
// The taxonomy file holds `'CRED-001': '...'` mapping keys (and, since r2,
// prose that cites the expression sites), not emission sites; everything
// else in src/ — in-src test fixtures included — counts, because that is
// the population the HMA-29 baseline measured (273 emitted ids, 50
// unmapped).
const SKIP_FILES = new Set([resolve(SRC_ROOT, 'hardening/taxonomy.ts')]);

const CHECKID_RE = /checkId:\s*(?:['"]([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)['"]|`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`)/g;
// SemanticFinding uses `id:`; finding-adapter.ts copies it into
// SecurityFinding.checkId. Same reading taxonomy-coverage.test.ts:86-88
// already does, scoped to src/semantic.
const SEMANTIC_ID_RE = /\bid:\s*(?:['"](SEM-[A-Z0-9-]+)['"]|`(SEM-[A-Z0-9-]+)`)/g;
// A checkId (or SemanticFinding/payload id) built as `PREFIX-${…}`: the
// static prefix is the family; the suffix is runtime data.
const TEMPLATE_RE = /\b(?:checkId|id):\s*`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)-\$\{/g;
// An expression-valued `checkId:` — the shape the r1 census was blind to
// (review finding 5). Captures up to the delimiter; the shape filter below
// keeps identifier chains (`ctrl.id`, `f.checkId || ''`) and drops TS type
// annotations and doc prose.
const EXPR_RE = /\bcheckId:\s*([^'"`\s][^,\n]*?)\s*[,}\n]/g;
const EXPR_SHAPE = /^[A-Za-z_$][\w$]*(?:\.[\w$]+(?:\(\))?)*(?: \|\| .+)?$/;
const TYPE_TOKENS = /^(?:string|number|boolean|null|undefined|any|unknown|never)$/;

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
  const semanticDir = join(SRC_ROOT, 'semantic');
  for (const file of walkTs(SRC_ROOT)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(CHECKID_RE)) {
      emitted.add(m[1] ?? m[2]!);
    }
    if (file.startsWith(semanticDir)) {
      for (const m of text.matchAll(SEMANTIC_ID_RE)) {
        emitted.add(m[1] ?? m[2]!);
      }
    }
  }
  return emitted;
}

/** `PREFIX` of every `PREFIX-${…}` template id, keyed by src-relative file. */
function collectTemplateFamilies(): Map<string, Set<string>> {
  const byFile = new Map<string, Set<string>>();
  for (const file of walkTs(SRC_ROOT)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(TEMPLATE_RE)) {
      const rel = relative(SRC_ROOT, file);
      if (!byFile.has(rel)) byFile.set(rel, new Set());
      byFile.get(rel)!.add(m[1]);
    }
  }
  return byFile;
}

/** Every expression-valued `checkId:` site as `"<src-relative file> :: <expression>"`. */
function collectExpressionSites(): Set<string> {
  const sites = new Set<string>();
  for (const file of walkTs(SRC_ROOT)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(EXPR_RE)) {
      const value = m[1].replace(/;+$/, '').trim();
      if (TYPE_TOKENS.test(value)) continue; // `checkId: string` type field
      if (!EXPR_SHAPE.test(value)) {
        // Type annotations and doc prose carry `:`/`{`/backticks or free
        // spaces; a genuinely new expression shape (ternary, call chain
        // with arguments) lands here and must be surfaced, not skipped.
        if (/[:{*`]/.test(value) || /\s/.test(value)) continue;
      }
      sites.add(`${relative(SRC_ROOT, file)} :: ${value}`);
    }
  }
  return sites;
}

/**
 * Every known expression-valued `checkId:` site, with how its ids are
 * covered. A new site fails the census until it is registered here with a
 * population (or shown to be a pass-through/user-input).
 *
 * - control-catalog: ids are CONTROL_DEFS ids (scan-soul contribution).
 * - scanner-id-literals: ids are the `id: '…'` literals of the LLM/AITOOL
 *   pattern arrays in scanner.ts.
 * - semantic-finding-ids: ids are the `id: 'SEM-…'` literals under
 *   src/semantic plus the SEM-LLM-NNN template.
 * - payload-templates: ids are the `FAMILY-${counter}` templates of
 *   attack-engine/payload-generator.ts.
 * - pass-through: re-emits the checkId of an existing finding produced by
 *   one of the covered sites; introduces no new ids.
 * - user-input: a `.hmaignore` rule's check id, matched against findings,
 *   never emitted as one.
 */
const EXPRESSION_SITES: Record<string, string> = {
  'cli.ts :: ctrl.id': 'control-catalog',
  'cli.ts :: f.checkId': 'pass-through',
  "cli.ts :: f.checkId || ''": 'pass-through',
  'cli.ts :: finding.checkId': 'pass-through',
  'hardening/scanner.ts :: check.id': 'scanner-id-literals',
  'hardening/scanner.ts :: f.checkId': 'pass-through',
  'hardening/scanner.ts :: pattern.toUpperCase()': 'user-input',
  'hardening/scanner.ts :: r.checkId': 'pass-through',
  'hardening/scanner.ts :: suffix.toUpperCase()': 'user-input',
  'mcp-server.ts :: f.checkId': 'pass-through',
  'nanomind-core/scanner-bridge.ts :: ast.checkId': 'pass-through',
  'registry/publish.ts :: c.id || c.checkId': 'pass-through',
  'registry/publish.ts :: f.checkId': 'pass-through',
  'registry/publish.ts :: r.payload.id': 'payload-templates',
  'semantic/integration/finding-adapter.ts :: finding.id': 'semantic-finding-ids',
  'ui/unresolved-categories.ts :: s.checkId': 'pass-through',
  'ui/verdict-band.ts :: row.checkId': 'pass-through',
};

/**
 * The census: emitted ids that are neither inventory keys nor declared
 * excluded. Factored over its inputs so the plant cells below can hand it
 * a doctored inventory or exclusion list and watch it fail on exactly the
 * planted id.
 */
function censusGap(
  emitted: ReadonlySet<string>,
  inventory: ReadonlySet<string>,
  isExcluded: (id: string) => boolean,
): string[] {
  return [...emitted].filter((id) => !inventory.has(id) && !isExcluded(id)).sort();
}

/** Entry-driven twin of isDeclaredExcludedCheckId, for the doctored-exclusions plants. */
function excludedByEntries(entries: readonly CheckIdExclusion[]): (id: string) => boolean {
  return (id) => entries.some((e) => checkIdExclusionMatches(e, id));
}

/** Template families not covered by a declared-exclusion family or per-id inventory keys. */
function uncoveredTemplateFamilies(
  templates: ReadonlyMap<string, Set<string>>,
  inventory: ReadonlySet<string>,
  exclusionFamilies: ReadonlySet<string>,
): string[] {
  const uncovered = new Set<string>();
  for (const families of templates.values()) {
    for (const family of families) {
      if (exclusionFamilies.has(family)) continue;
      if ([...inventory].some((k) => k.startsWith(`${family}-`))) continue;
      uncovered.add(family);
    }
  }
  return [...uncovered].sort();
}

const emitted = collectEmittedCheckIds();
const inventory = new Set(Object.keys(getTaxonomyMap()));
const exclusions = getDeclaredCheckIdExclusions();
const exclusionFamilies = new Set(exclusions.map((e) => e.family));
const templates = collectTemplateFamilies();

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

  it('HMA-29.AC4 the declared-exclusion entries and isDeclaredExcludedCheckId agree', () => {
    // The plants below doctor the entry list and match with
    // checkIdExclusionMatches; this cell pins that matcher to the predicate
    // the shipping census check uses, over the whole census population plus
    // one representative of every dynamic family.
    const byEntries = excludedByEntries(exclusions);
    const probes = [
      ...emitted,
      ...CONTROL_DEFS.map((c) => c.id),
      'ARP-1', 'SEM-LLM-042', 'ADAPT-3', 'INJECT-17', 'INJECT-001',
      'SKILL-SEMANTIC-007', 'CRED-001', 'ZZZQ-123',
    ];
    for (const id of probes) {
      expect(byEntries(id), `entry matcher and predicate disagree on ${id}`).toBe(
        isDeclaredExcludedCheckId(id),
      );
    }
  });
});

describe('HMA-29.AC5 — the emission shapes the r1 census could not see', () => {
  it('HMA-29.AC5 the eight SEM-MCP ids (emitted as `id:` under src/semantic) are inventory keys with their inline classes', () => {
    // Red at 3a0ac37e: `secure --ci --json test-fixtures` emitted
    // SEM-MCP-001 at critical while `explain SEM-MCP-001` exited 1 and
    // check-metadata denied the id exists (r1 review finding 1).
    const expected: Record<string, string> = {
      'SEM-MCP-001': 'MCP-PRIV-ESC',
      'SEM-MCP-002': 'MCP-PRIV-ESC',
      'SEM-MCP-003': 'MCP-CRED',
      'SEM-MCP-004': 'MCP-SCOPE-WILDCARD',
      'SEM-MCP-005': 'MCP-CHAIN-EXFIL',
      'SEM-MCP-006': 'MCP-SCOPE-EXPAND',
      'SEM-MCP-007': 'MCP-TYPOSQUAT',
      'SEM-MCP-008': 'MCP-SUPPLY-CHAIN',
    };
    for (const [id, attackClass] of Object.entries(expected)) {
      expect(emitted.has(id), `${id} must be read by the semantic-id shape`).toBe(true);
      expect(inventory.has(id), `${id} must be a TAXONOMY_MAP key`).toBe(true);
      expect(getAttackClass(id), `${id} class must mirror its emission site`).toBe(attackClass);
    }
    // And they are counted, not just present: SEM-MCP ids are semantic.
    expect(getCheckCounts().semantic).toBeGreaterThanOrEqual(45);
  });

  it('HMA-29.AC5 plant (semantic-id shape): SEM-MCP-001 removed from the inventory is reported as exactly that id', () => {
    const doctored = new Set(inventory);
    doctored.delete('SEM-MCP-001');
    expect(censusGap(emitted, doctored, isDeclaredExcludedCheckId)).toEqual(['SEM-MCP-001']);
  });

  it('HMA-29.AC5 every `PREFIX-${…}` template family is declared-excluded or keyed', () => {
    // The shapes the r1 census was blind to: ARP-${pattern.id}
    // (eval/oracle.ts), SEM-LLM-NNN (semantic/llm/index.ts), the payload
    // counters (attack-engine/payload-generator.ts), and the NanoMind
    // daemon narrative families (semantic/nanomind-analyzer.ts).
    const allFamilies = new Set([...templates.values()].flatMap((s) => [...s]));
    for (const family of ['ARP', 'SEM-LLM', 'ADAPT', 'INJECT', 'MCP-SEMANTIC', 'SKILL-SEMANTIC']) {
      expect(allFamilies.has(family), `template family ${family} must be read by the walk`).toBe(true);
    }
    expect(uncoveredTemplateFamilies(templates, inventory, exclusionFamilies)).toEqual([]);
  });

  it('HMA-29.AC5 plant (template shape): with the ARP exclusion dropped, exactly ARP is reported', () => {
    const doctored = new Set(
      exclusions.filter((e) => e.family !== 'ARP').map((e) => e.family),
    );
    expect(uncoveredTemplateFamilies(templates, inventory, doctored)).toEqual(['ARP']);
  });

  it('HMA-29.AC5 the scan-soul control catalogue is declared: every CONTROL_DEFS id is keyed or excluded', () => {
    // Red at 3a0ac37e (review finding 5): 49 of the 72 control ids were
    // emitted at cli.ts (`checkId: ctrl.id`) while being neither inventory
    // keys nor declared exclusions.
    const controlIds = CONTROL_DEFS.map((c) => c.id);
    expect(controlIds.length).toBeGreaterThan(50);
    const uncovered = controlIds.filter(
      (id) => !inventory.has(id) && !isDeclaredExcludedCheckId(id),
    );
    expect(uncovered, 'control ids neither keyed nor declared-excluded').toEqual([]);

    const soulEntry = exclusions.find((e) => e.family === 'SOUL');
    expect(soulEntry, 'check-metadata must declare the scan-soul catalogue exclusion').toBeDefined();
    const outsideMap = controlIds.filter((id) => !inventory.has(id)).sort();
    expect(soulEntry!.ids).toEqual(outsideMap);
    expect(soulEntry!.ids).toContain('SOUL-TH-006');
    expect(soulEntry!.reason).toMatch(/explain/i);
  });

  it('HMA-29.AC5 plant (ctrl.id shape): with the catalogue exclusion dropped, the uncovered control ids are reported', () => {
    const doctored = excludedByEntries(exclusions.filter((e) => e.family !== 'SOUL'));
    const uncovered = CONTROL_DEFS.map((c) => c.id).filter(
      (id) => !inventory.has(id) && !doctored(id),
    );
    expect(uncovered.length).toBeGreaterThan(40);
    expect(uncovered).toContain('SOUL-TH-006');
  });

  it('HMA-29.AC5 every expression-valued checkId site is registered with its population', () => {
    const found = [...collectExpressionSites()].sort();
    expect(found).toEqual(Object.keys(EXPRESSION_SITES).sort());

    // Resolve each population-bearing site:
    // check.id → the LLM/AITOOL `id: '…'` literals of scanner.ts.
    const scannerText = readFileSync(join(SRC_ROOT, 'hardening/scanner.ts'), 'utf8');
    const scannerIds = new Set(
      [...scannerText.matchAll(/\bid:\s*'([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)'/g)].map((m) => m[1]),
    );
    expect(scannerIds.size).toBeGreaterThanOrEqual(8);
    expect(scannerIds.has('LLM-001')).toBe(true);
    expect(scannerIds.has('AITOOL-001')).toBe(true);
    const scannerGap = censusGap(scannerIds, inventory, isDeclaredExcludedCheckId);
    expect(scannerGap, 'scanner check.id populations must be keyed or excluded').toEqual([]);

    // r.payload.id → the payload counter templates; every family declared.
    const payloadFamilies = templates.get('attack-engine/payload-generator.ts');
    expect(payloadFamilies).toBeDefined();
    expect(payloadFamilies!.size).toBeGreaterThanOrEqual(8);
    for (const family of payloadFamilies!) {
      expect(exclusionFamilies.has(family), `payload family ${family} must be declared`).toBe(true);
    }

    // finding.id → the semantic `id:` literals (already in `emitted`) plus
    // the SEM-LLM template family.
    expect(emitted.has('SEM-MCP-001')).toBe(true);
    expect(exclusionFamilies.has('SEM-LLM')).toBe(true);
    // ctrl.id → covered by the control-catalogue cell above.
  });

  it('HMA-29.AC5 plant (expression-site shape): an unregistered site is reported as exactly that site', () => {
    const registry = new Set(Object.keys(EXPRESSION_SITES));
    registry.delete('registry/publish.ts :: r.payload.id');
    const unregistered = [...collectExpressionSites()].filter((s) => !registry.has(s));
    expect(unregistered).toEqual(['registry/publish.ts :: r.payload.id']);
  });
});

describe('HMA-29.AC7 — inventory severity agrees with fixed-severity emission sites', () => {
  it.each([
    ['AST-MANIP-001', 'critical'],
    ['AST-HEARTBEAT-001', 'critical'],
    ['AST-INJECT-001', 'critical'],
    ['AST-GOV-004', 'high'],
    ['AST-PERSIST-001', 'high'],
    ['SOUL-UNVERIFIABLE-CLAIM', 'medium'],
  ] as const)('HMA-29.AC7 getCheckSeverity(%s) matches the emission site (%s)', (id, severity) => {
    // Red at 3a0ac37e (review finding 4): all 26 AST entries reported the
    // medium prefix default while these sites emit one fixed severity, and
    // SOUL-UNVERIFIABLE-CLAIM reported the SOUL default high vs emitted
    // medium.
    expect(getCheckSeverity(id)).toBe(severity);
  });
});

describe('HMA-29.AC3 — the inventory covers, or declares its exclusion of, every emitted family', () => {
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
      expect(ex.family).toMatch(/^[A-Z][A-Z0-9-]*$/);
      expect(ex.reason.length, `${ex.family} exclusion must say WHY`).toBeGreaterThan(20);
    }
    const families = exclusions.map((e) => e.family);
    for (const fam of ['CHK', 'FIX', 'SCAN', 'SEM', 'SOUL', 'ARP', 'SEM-LLM']) {
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
    // check id is neither exempt nor family-excluded, and the payload-counter
    // patterns spare the zero-padded ids of the same prefix.
    expect(isDeclaredExcludedCheckId('CRED-001')).toBe(false);
    expect(isDeclaredExcludedCheckId('AST-CRED-001')).toBe(false);
    expect(isDeclaredExcludedCheckId('SEM-MCP-001')).toBe(false);
    expect(isDeclaredExcludedCheckId('INJECT-001')).toBe(false);
    expect(isDeclaredExcludedCheckId('INJECT-17')).toBe(true);
  });
});

describe.runIf(existsSync(CLI))('HMA-29.AC3 — check-metadata carries the coverage and the exclusions (spawn)', () => {
  beforeAll(assertDistFreshIfPresent);

  it('HMA-29.AC3 check-metadata --json: totalChecks reflects the added ids and exclusions are declared', () => {
    const res = spawnSync(process.execPath, [CLI, 'check-metadata', '--json'], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    expect(res.status).toBe(0);
    const payload = JSON.parse(res.stdout);

    expect(payload.totalChecks).toBe(getCheckCounts().total);
    expect(payload.checks['AST-CRED-001']).toBeDefined();
    expect(payload.checks['SOUL-CONTRADICTION']).toBeDefined();
    expect(payload.checks['SEM-MCP-001']).toBeDefined();

    expect(Array.isArray(payload.exclusions)).toBe(true);
    const byFamily = new Map<string, { family: string; ids: string[]; pattern?: string; reason: string }>(
      payload.exclusions.map((e: { family: string; ids: string[]; reason: string }) => [e.family, e]),
    );
    for (const fam of ['CHK', 'FIX', 'SCAN', 'SEM', 'SOUL', 'ARP', 'SEM-LLM', 'INJECT']) {
      const ex = byFamily.get(fam);
      expect(ex, `check-metadata must declare the ${fam} exclusion`).toBeDefined();
      expect(ex!.reason.length).toBeGreaterThan(20);
    }
    expect(byFamily.get('FIX')!.ids).toContain('FIX-SUMMARY');
    expect(byFamily.get('SEM')!.ids).toContain('SEM-LLM-NOT-ANALYZED');
    expect(byFamily.get('SOUL')!.ids).toContain('SOUL-TH-006');
    expect(byFamily.get('INJECT')!.pattern).toBeDefined();
  });

  it('HMA-29.AC7 check-metadata --json: severityNote documents per-finding AST severity and the pinned sites match', () => {
    const res = spawnSync(process.execPath, [CLI, 'check-metadata', '--json'], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    expect(res.status).toBe(0);
    const payload = JSON.parse(res.stdout);
    expect(payload.severityNote).toMatch(/AST/);
    expect(payload.severityNote).toMatch(/per finding/i);
    expect(payload.checks['AST-MANIP-001'].severity).toBe('critical');
    expect(payload.checks['AST-HEARTBEAT-001'].severity).toBe('critical');
    expect(payload.checks['AST-INJECT-001'].severity).toBe('critical');
    expect(payload.checks['AST-GOV-004'].severity).toBe('high');
    expect(payload.checks['AST-PERSIST-001'].severity).toBe('high');
    expect(payload.checks['SOUL-UNVERIFIABLE-CLAIM'].severity).toBe('medium');
  });
});
