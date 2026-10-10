import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import * as taxonomy from '../../src/hardening/taxonomy';

/**
 * The family codes in TAXONOMY_MAP (MCP-EXPLOIT, SOUL-INJECT, ...) are not
 * attack classes. The ten canonical classes are the objective an attacker
 * pursues; a family names the surface a check inspects. Before this suite
 * nothing in the code stated which class a family belongs to, so a consumer
 * that needed a class stored the family string in its place, and nothing
 * stated that one condition detected by both layers (a filesystem MCP server
 * with unscoped reach: MCP-001 as MCP-EXPLOIT, SEM-MCP-001 as MCP-PRIV-ESC)
 * is one family.
 *
 * The namespace import keeps the file loading before the exports exist, so
 * each case fails on its own assertion rather than the whole file failing to
 * import.
 */

const TEN = [
  'injection',
  'exfiltration',
  'credential_abuse',
  'privilege_escalation',
  'persistence',
  'lateral_movement',
  'social_engineering',
  'policy_violation',
  'steganography',
  'benign',
];

type Api = {
  CANONICAL_CLASSES?: readonly string[];
  FAMILY_CLASS?: Readonly<Record<string, string>>;
  FAMILY_FOLDS?: Readonly<Record<string, string>>;
  getCanonicalClass?: (family: string) => string;
};
const api = taxonomy as unknown as Api;

function familyClass(): Readonly<Record<string, string>> {
  expect(api.FAMILY_CLASS, 'taxonomy exports FAMILY_CLASS').toBeTypeOf('object');
  return api.FAMILY_CLASS as Readonly<Record<string, string>>;
}

function familyFolds(): Readonly<Record<string, string>> {
  expect(api.FAMILY_FOLDS, 'taxonomy exports FAMILY_FOLDS').toBeTypeOf('object');
  return api.FAMILY_FOLDS as Readonly<Record<string, string>>;
}

function canonical(family: string): string {
  expect(api.getCanonicalClass, 'taxonomy exports getCanonicalClass').toBeTypeOf('function');
  return (api.getCanonicalClass as (f: string) => string)(family);
}

describe('family code to canonical class normalisation', () => {
  it('refuses an unknown family instead of passing it through', () => {
    expect(() => canonical('NOT-A-FAMILY')).toThrow('unknown attack family: NOT-A-FAMILY');
    // A canonical class is not a family either: handing one back in is refused,
    // so a value that was already normalised cannot be normalised "again".
    expect(() => canonical('injection')).toThrow('unknown attack family: injection');
    expect(() => canonical('')).toThrow('unknown attack family: ');
  });

  it('every family TAXONOMY_MAP assigns is a FAMILY_CLASS family or a fold alias', () => {
    const map = familyClass();
    const folds = familyFolds();
    const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
    const missing = [...new Set(Object.values(taxonomy.getTaxonomyMap()))]
      .filter((family) => !has(map, family) && !has(folds, family))
      .sort();
    expect(missing).toEqual([]);
    for (const family of Object.values(taxonomy.getTaxonomyMap())) {
      expect(TEN).toContain(canonical(family));
    }
  });

  it('every class FAMILY_CLASS assigns is one of the ten', () => {
    expect([...(api.CANONICAL_CLASSES ?? [])].sort()).toEqual([...TEN].sort());
    const outside = Object.entries(familyClass()).filter(([, cls]) => !TEN.includes(cls));
    expect(outside).toEqual([]);
  });

  it('holds 69 families, each under exactly one class', () => {
    const map = familyClass();
    expect(Object.keys(map)).toHaveLength(69);
    const perClass: Record<string, number> = {};
    for (const cls of Object.values(map)) perClass[cls] = (perClass[cls] ?? 0) + 1;
    expect(perClass).toEqual({
      injection: 20,
      exfiltration: 4,
      credential_abuse: 6,
      privilege_escalation: 18,
      persistence: 3,
      lateral_movement: 1,
      social_engineering: 1,
      policy_violation: 16,
    });
  });

  it('Layer 1 MCP-001 and Layer 2 SEM-MCP-001 resolve to one family and one class', () => {
    expect(familyFolds()['MCP-PRIV-ESC']).toBe('MCP-EXPLOIT');
    expect(taxonomy.getAttackClass('MCP-001')).toBe('MCP-EXPLOIT');
    const layer1 = canonical(taxonomy.getAttackClass('MCP-001') as string);
    const layer2 = canonical(taxonomy.getAttackClass('SEM-MCP-001') as string);
    expect(layer2).toBe(layer1);
    expect(layer1).toBe('privilege_escalation');
  });

  it('each fold alias points at a FAMILY_CLASS family, is not one itself, and takes its class', () => {
    const map = familyClass();
    const folds = familyFolds();
    expect(folds).toEqual({
      'MCP-PRIV-ESC': 'MCP-EXPLOIT',
      'CMD-INJECT': 'CODE-INJECTION',
      'PROMPT-INJECT': 'SOUL-INJECT',
      'PERSISTENCE': 'PERSIST-STATE',
    });
    for (const [alias, target] of Object.entries(folds)) {
      expect(Object.prototype.hasOwnProperty.call(map, alias), `${alias} is not a family`).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(map, target), `${target} is a family`).toBe(true);
      expect(canonical(alias)).toBe(map[target]);
    }
  });

  it('the four Harm Avoidance controls are one family, SOUL-HV', () => {
    for (const id of ['SOUL-HV-001', 'SOUL-HV-002', 'SOUL-HV-003', 'SOUL-HV-004']) {
      expect(taxonomy.getAttackClass(id)).toBe('SOUL-HV');
    }
    const families = new Set([
      ...Object.values(taxonomy.getTaxonomyMap()),
      ...Object.keys(familyClass()),
    ]);
    expect([...families].filter((f) => /^SOUL-HV-\d+$/.test(f))).toEqual([]);
    expect(canonical('SOUL-HV')).toBe('policy_violation');
  });
});

describe('check-metadata --json canonicalClass', () => {
  beforeAll(assertDistFresh);

  it('every check carries canonicalClass beside its unchanged attackClass', () => {
    const res = spawnSync(process.execPath, [CLI, 'check-metadata', '--json'], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    expect(res.status).toBe(0);
    const checks = JSON.parse(res.stdout).checks as Record<
      string,
      { attackClass: string; canonicalClass?: string }
    >;
    const wrong = Object.entries(checks)
      .filter(([id, c]) => c.attackClass !== taxonomy.getAttackClass(id)
        || c.canonicalClass !== canonical(c.attackClass))
      .map(([id, c]) => `${id}: ${c.attackClass} -> ${c.canonicalClass}`);
    expect(wrong).toEqual([]);
    expect(checks['MCP-001'].canonicalClass).toBe('privilege_escalation');
    expect(checks['SEM-MCP-001']).toMatchObject({
      attackClass: 'MCP-PRIV-ESC',
      canonicalClass: 'privilege_escalation',
    });
    expect(checks['SOUL-HV-001']).toMatchObject({
      attackClass: 'SOUL-HV',
      canonicalClass: 'policy_violation',
    });
  });
});
