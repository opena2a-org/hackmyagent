/**
 * The check-definition table names each check the way its findings do, so
 * `explain` and `check-metadata` cannot drift from what `secure` prints.
 *
 * src/hardening/check-definitions.ts copies each check's name, description,
 * guidance and fix from the site that pushes the finding. This file parses
 * those sites with the TypeScript compiler, starting with
 * src/hardening/scanner.ts, and holds the table to them in both directions:
 *
 * - every id a push site gives a literal name, and that the check inventory
 *   counts, has an entry, and the pushed name is the entry's name or one of
 *   its altNames;
 * - where every push site of an id names it literally, the entry lists no
 *   name those sites do not push, so a renamed finding cannot leave its old
 *   name behind in the table;
 * - where the push sites of an id give one literal fix between them, the
 *   entry's fix is that fix, so a fix changed at its push site cannot leave
 *   the old one in what `explain` prints. The DEP-004 entry kept
 *   `npm install --save-exact <package>` after its push site moved to the
 *   fail-closed operand, and a comparison of names alone did not see it.
 *
 * An id pushed by more than one module is held to the module that owns it,
 * in EMITTERS order: the simulation probes and the plugins reuse some
 * scanner ids for findings of their own, and the table describes the
 * scanner's check. A pushed id the inventory does not count (FIX-SUMMARY,
 * SCAN-UNREAD-001 and the other run records) is outside the table;
 * checkid-census.test.ts already requires every emitted id to be counted or
 * declared, so a new check cannot skip this file by staying out of the
 * inventory.
 */
import { describe, it, expect } from 'vitest';
import ts from 'typescript';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CHECK_DEFINITIONS } from '../../src/hardening/check-definitions';
import { getCountedCheckIds } from '../../src/hardening/taxonomy';

const ROOT = join(__dirname, '..', '..');

function tsFilesIn(dir: string): string[] {
  return readdirSync(join(ROOT, dir))
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .sort()
    .map((f) => `${dir}/${f}`);
}

/** The modules that push findings, in ownership order. */
const EMITTERS: readonly (readonly string[])[] = [
  ['src/hardening/scanner.ts'],
  ['src/hardening/skill-capability-validator.ts'],
  tsFilesIn('src/nanomind-core/analyzers'),
  tsFilesIn('src/semantic/structural'),
  ['src/lifecycle/assembly-scanner.ts'],
  ['src/scanner/external-scanner.ts'],
  ['src/simulation/probes.ts'],
];

interface PushSite {
  where: string;
  /** The names the site can push, or null when one is computed at run time. */
  names: string[] | null;
  /**
   * The fixes the site can push, or null when one is computed at run time.
   * A branch that pushes no fix (`undefined`) adds nothing.
   */
  fixes: string[] | null;
}

/**
 * Whether a spread at a push site can carry a `fix`. A spread of object
 * literals written out in place is read key by key, so
 * `...(matched ? { line } : {})` adds a line and no fix; any other spread
 * might carry one.
 */
function spreadCanSupplyFix(node: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(node)) return spreadCanSupplyFix(node.expression);
  if (ts.isConditionalExpression(node)) return spreadCanSupplyFix(node.whenTrue) || spreadCanSupplyFix(node.whenFalse);
  if (!ts.isObjectLiteralExpression(node)) return true;
  return node.properties.some((p) => {
    if (ts.isSpreadAssignment(p)) return spreadCanSupplyFix(p.expression);
    if (ts.isComputedPropertyName(p.name)) return true;
    return (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && p.name.text === 'fix';
  });
}

function literalStrings(node: ts.Expression, allowUndefined = false): string[] | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (allowUndefined && ts.isIdentifier(node) && node.text === 'undefined') return [];
  if (ts.isParenthesizedExpression(node)) return literalStrings(node.expression, allowUndefined);
  if (ts.isConditionalExpression(node)) {
    const whenTrue = literalStrings(node.whenTrue, allowUndefined);
    const whenFalse = literalStrings(node.whenFalse, allowUndefined);
    return whenTrue && whenFalse ? [...whenTrue, ...whenFalse] : null;
  }
  return null;
}

/** Every object literal with a literal `checkId` (or `id`) and a `name` (or `title`). */
function pushSites(file: string): Map<string, PushSite[]> {
  const sf = ts.createSourceFile(file, readFileSync(join(ROOT, file), 'utf-8'), ts.ScriptTarget.Latest, true);
  const sites = new Map<string, PushSite[]>();
  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      const props = new Map<string, ts.Expression>();
      // A shorthand `fix`, or a spread that can carry one, supplies the fix;
      // neither is a literal.
      let computedFix = false;
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) props.set(p.name.text, p.initializer);
        if (ts.isShorthandPropertyAssignment(p) && p.name.text === 'fix') computedFix = true;
        if (ts.isSpreadAssignment(p) && spreadCanSupplyFix(p.expression)) computedFix = true;
      }
      const idNode = props.get('checkId') ?? props.get('id');
      const nameNode = props.get('name') ?? props.get('title');
      const fixNode = props.get('fix');
      if (idNode && nameNode && (ts.isStringLiteral(idNode) || ts.isNoSubstitutionTemplateLiteral(idNode))) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        const list = sites.get(idNode.text) ?? [];
        list.push({
          where: `${file}:${line}`,
          names: literalStrings(nameNode),
          fixes: computedFix ? null : fixNode ? literalStrings(fixNode, true) : [],
        });
        sites.set(idNode.text, list);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return sites;
}

const counted = new Set(getCountedCheckIds());

/** Each counted id's push sites in the module that owns it. */
const OWNED = new Map<string, PushSite[]>();
const SCANNER_IDS = new Set<string>();
for (const [i, bucket] of EMITTERS.entries()) {
  const found = new Map<string, PushSite[]>();
  for (const file of bucket) {
    for (const [id, list] of pushSites(file)) found.set(id, [...(found.get(id) ?? []), ...list]);
  }
  for (const [id, list] of found) {
    if (!counted.has(id) || OWNED.has(id)) continue;
    OWNED.set(id, list);
    if (i === 0) SCANNER_IDS.add(id);
  }
}

/** Each owned id whose push sites all give their fix literally, and give one fix between them. */
const ONE_LITERAL_FIX = new Map<string, string>();
for (const [id, list] of OWNED) {
  if (list.some((s) => s.fixes === null)) continue;
  const pushed = [...new Set(list.flatMap((s) => s.fixes ?? []))];
  if (pushed.length === 1) ONE_LITERAL_FIX.set(id, pushed[0]);
}

function tableNames(id: string): string[] {
  const def = CHECK_DEFINITIONS[id];
  return def ? [def.name, ...(def.altNames ?? [])] : [];
}

describe('the check-definition table matches the push sites', () => {
  it('the walk finds the push sites (non-vacuity)', () => {
    expect(SCANNER_IDS.size).toBeGreaterThan(150);
    expect(OWNED.size).toBeGreaterThan(250);
    // Two sites read by hand: the walk sees their names.
    expect(OWNED.get('DEP-004')?.some((s) => s.names?.includes('Dangerous npm Scripts'))).toBe(true);
    expect(OWNED.get('PROC-001')?.some((s) => s.names?.includes('Container User'))).toBe(true);
  });

  it('every id scanner.ts pushes has an entry', () => {
    const missing = [...SCANNER_IDS].filter((id) => !CHECK_DEFINITIONS[id]);
    expect(missing, `pushed by scanner.ts, not in the table: ${missing.join(', ')}`).toEqual([]);
  });

  it('every pushed id has an entry, and every counted check has one', () => {
    const missing = [...new Set([...OWNED.keys(), ...counted])].filter((id) => !CHECK_DEFINITIONS[id]);
    expect(missing, `no table entry: ${missing.join(', ')}`).toEqual([]);
  });

  it('every name a push site gives is the entry\'s name or one of its altNames', () => {
    const drift: string[] = [];
    for (const [id, list] of OWNED) {
      const listed = tableNames(id);
      for (const site of list) {
        for (const name of site.names ?? []) {
          if (!listed.includes(name)) drift.push(`${id} at ${site.where} pushes "${name}"; the table lists ${JSON.stringify(listed)}`);
        }
      }
    }
    expect(drift).toEqual([]);
  });

  it('where every site names its id literally, the entry lists only names those sites push', () => {
    const stale: string[] = [];
    for (const [id, list] of OWNED) {
      if (list.some((s) => s.names === null)) continue;
      const pushed = new Set(list.flatMap((s) => s.names ?? []));
      for (const name of tableNames(id)) {
        if (!pushed.has(name)) stale.push(`${id}: the table lists "${name}", which no push site gives`);
      }
    }
    expect(stale).toEqual([]);
  });

  it('the walk reads the fix a site pushes (non-vacuity)', () => {
    // DEP-004 pushes its fix only on a failing scan, behind a conditional,
    // beside a spread that adds the line it matched and no fix.
    const dep004 = (OWNED.get('DEP-004') ?? []).flatMap((s) => s.fixes ?? []);
    expect(dep004.some((f) => f.startsWith('Remove the curl|sh or wget|sh pattern'))).toBe(true);
    expect(ONE_LITERAL_FIX.size).toBeGreaterThan(100);
  });

  it('where the push sites give one literal fix, the entry carries that fix', () => {
    // `explain` prints the entry's fix as the fix of the check, so an entry
    // copied once and left behind when the push site changed prints a remedy
    // the finding no longer gives. An id whose sites give several fixes, or
    // build one at run time, is stated in general terms and not held here.
    const drift: string[] = [];
    for (const [id, pushed] of ONE_LITERAL_FIX) {
      const fix = CHECK_DEFINITIONS[id]?.fix;
      if (fix !== pushed) drift.push(`${id}: the table's fix is ${JSON.stringify(fix)}; the push sites give ${JSON.stringify(pushed)}`);
    }
    expect(drift).toEqual([]);
  });
});
