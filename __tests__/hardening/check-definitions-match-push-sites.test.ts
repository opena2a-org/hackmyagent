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
 *   name behind in the table.
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
}

function literalStrings(node: ts.Expression): string[] | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (ts.isParenthesizedExpression(node)) return literalStrings(node.expression);
  if (ts.isConditionalExpression(node)) {
    const whenTrue = literalStrings(node.whenTrue);
    const whenFalse = literalStrings(node.whenFalse);
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
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) props.set(p.name.text, p.initializer);
      }
      const idNode = props.get('checkId') ?? props.get('id');
      const nameNode = props.get('name') ?? props.get('title');
      if (idNode && nameNode && (ts.isStringLiteral(idNode) || ts.isNoSubstitutionTemplateLiteral(idNode))) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        const list = sites.get(idNode.text) ?? [];
        list.push({ where: `${file}:${line}`, names: literalStrings(nameNode) });
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
});
