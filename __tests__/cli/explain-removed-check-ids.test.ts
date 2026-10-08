/**
 * `explain` answers the check IDs #395 removed, and nothing else still
 * files a finding under their families.
 *
 * CODEINJ-001, TMPPATH-001 and ENVLEAK-001 were deleted in #395, but a
 * `.hmaignore` line, a saved report or a script can still carry one.
 * `explain TMPPATH-001` answered "Unknown check ID", suggested AUTH-001,
 * CLIPASS-001 and DATA-001, and exited 1, so nothing pointed at the check
 * that remains (#901). Each removed ID now says it is removed and names the
 * remaining check: NEMO-005, NEMO-006 and NEMO-007.
 *
 * The removed IDs are read from the `<ID> removed` notes in scanner.ts and
 * taxonomy.ts, the record coverage-honesty.test.ts also reads, so a check
 * removed later without an explain entry fails here.
 *
 * #914: the checks a removed entry points to explain themselves instead of
 * printing the generic "Static analysis pattern finding.", the Next Steps
 * block under a removed ID names the remaining check instead of a scan that
 * cannot show it, and the narrative's credential prefix list is held to the
 * same no-dead-family rule as the other tables.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { REMOVED_CHECKS, STATIC_EXPLANATIONS, isKnownExplainId } from '../../src/explain-registry';
import { CREDENTIAL_ATTACK_PREFIXES } from '../../src/narrative/build-narrative';
import { getTaxonomyMap } from '../../src/hardening/taxonomy';
import {
  CHECK_METHOD_PREFIXES,
  SEMANTIC_PREFIXES,
  categoryForCheckId,
} from '../../src/hardening/coverage-ledger';

beforeAll(assertDistFreshIfPresent);

const SRC = join(__dirname, '..', '..', 'src', 'hardening');
const SCANNER_SRC = readFileSync(join(SRC, 'scanner.ts'), 'utf-8');
const TAXONOMY_SRC = readFileSync(join(SRC, 'taxonomy.ts'), 'utf-8');

const REMOVED_IDS = [
  ...new Set(
    [...`${SCANNER_SRC}\n${TAXONOMY_SRC}`.matchAll(/\b([A-Z][A-Z0-9-]*-\d+) removed\b/g)].map(m => m[1]),
  ),
].sort();

/** The family prefix of a check ID: `TMPPATH-001` -> `TMPPATH`. */
const familyOf = (id: string) => id.replace(/-\d+$/, '');

/** Families some registered check method or the semantic layer still emits. */
const LIVE_FAMILIES = new Set<string>([
  ...Object.values(CHECK_METHOD_PREFIXES).flat(),
  ...SEMANTIC_PREFIXES,
]);

/** Families every removed ID belongs to that no remaining check emits. */
const DEAD_FAMILIES = [...new Set(REMOVED_IDS.map(familyOf))].filter(f => !LIVE_FAMILIES.has(f));

const REPLACEMENT: Record<string, string> = {
  'CODEINJ-001': 'NEMO-005',
  'TMPPATH-001': 'NEMO-006',
  'ENVLEAK-001': 'NEMO-007',
};

/** A phrase from each remaining check's own matcher or fix. */
const DESCRIBES: Record<string, RegExp> = {
  'NEMO-005': /execFile\(\)/,
  'NEMO-006': /mktemp/,
  'NEMO-007': /process\.env/,
};

describe('explain knows every check ID the code records as removed', () => {
  it('reads the removed IDs from the source (non-vacuity)', () => {
    expect(REMOVED_IDS).toEqual(expect.arrayContaining(Object.keys(REPLACEMENT)));
  });

  it('the removed-check table lists exactly the removed IDs, each with its remaining check', () => {
    expect(Object.keys(REMOVED_CHECKS).sort()).toEqual(REMOVED_IDS);
    expect({ ...REMOVED_CHECKS }).toEqual(expect.objectContaining(REPLACEMENT));
  });

  it.each(Object.entries(DESCRIBES))('%s, which a removed entry points to, has its own explanation', (id, phrase) => {
    const text = STATIC_EXPLANATIONS[id];
    expect(text, `explain ${id} falls back to the generic prefix line`).toBeTruthy();
    expect(text).not.toMatch(/\bremoved\b/i);
    expect(text).toMatch(/\bFix:/);
    expect(text).toMatch(phrase);
  });

  it.each(REMOVED_IDS)('%s is answered, says it is removed and names a check that remains', (id) => {
    expect(isKnownExplainId(id)).toBe(true);
    const text = STATIC_EXPLANATIONS[id];
    expect(text, `no explain entry for removed check ${id}`).toBeTruthy();
    expect(text).toMatch(/\bremoved\b/i);
    // Not counted in the advertised suite: answering it must not bring it back.
    expect(getTaxonomyMap()[id]).toBeUndefined();

    const taxonomy = getTaxonomyMap();
    const named = [...text.matchAll(/\b[A-Z][A-Z0-9-]*-\d+\b/g)].map(m => m[0]);
    const remaining = named.filter(n => n in taxonomy && !REMOVED_IDS.includes(n));
    expect(remaining.length, `${id} names no remaining check`).toBeGreaterThan(0);
    if (REPLACEMENT[id]) expect(remaining).toContain(REPLACEMENT[id]);
  });
});

describe('no table files a finding under a family nothing emits', () => {
  it('the removed families are no longer emitted (non-vacuity)', () => {
    expect(DEAD_FAMILIES).toEqual(expect.arrayContaining(['CODEINJ', 'TMPPATH', 'ENVLEAK']));
  });

  it.each(DEAD_FAMILIES)('the coverage category map has no entry for %s', (family) => {
    expect(categoryForCheckId(`${family}-001`)).toBeNull();
  });

  it('the narrative credential prefix list is read (non-vacuity)', () => {
    expect(CREDENTIAL_ATTACK_PREFIXES).toContain('CRED-');
  });

  it.each(DEAD_FAMILIES)('the narrative credential prefix list has no entry for %s', (family) => {
    const covering = CREDENTIAL_ATTACK_PREFIXES.filter(p => p.startsWith(family) || `${family}-`.startsWith(p));
    expect(covering).toEqual([]);
  });

  it.each(DEAD_FAMILIES)('the project-type map has no entry for %s', (family) => {
    const start = SCANNER_SRC.indexOf('const CHECK_PROJECT_TYPES');
    expect(start).toBeGreaterThan(-1);
    const block = SCANNER_SRC.slice(start, SCANNER_SRC.indexOf('\n};', start));
    expect(block).not.toMatch(new RegExp(`'${family}-`));
  });
});

// This block spawns the built CLI: a checkout that has not built fails it by
// name, with the command to run, and the source-only blocks above still report
// on their own.
describe('explain on a removed check ID (spawn)', () => {
  beforeAll(assertDistFresh);

  const explain = (id: string) =>
    spawnSync(process.execPath, [CLI, 'explain', id], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1', NANOMIND_URL: 'http://127.0.0.1:9' },
    });

  /** The lines after the Next Steps rule. */
  const nextSteps = (stdout: string) => stdout.slice(stdout.indexOf('Next Steps'));

  it.each(Object.entries(REPLACEMENT))('explain %s exits 0 and names %s', (id, replacement) => {
    const res = explain(id);
    expect(res.stderr ?? '').not.toMatch(/Unknown check ID/i);
    expect(res.stdout).toMatch(id);
    expect(res.stdout).toMatch(/\bremoved\b/i);
    expect(res.stdout).toMatch(replacement);
    expect(res.status).toBe(0);
  });

  // No finding carries a removed ID, so `secure --verbose` cannot show it in
  // context (#914).
  it.each(Object.entries(REPLACEMENT))('explain %s points Next Steps at %s, not at a scan', (id, replacement) => {
    const res = explain(id);
    expect(res.stdout).toMatch(/Next Steps/);
    const steps = nextSteps(res.stdout);
    expect(steps).not.toMatch(/secure --verbose/);
    expect(steps).toMatch(new RegExp(`explain ${replacement}\\b`));
  });

  it.each(Object.entries(DESCRIBES))('explain %s describes the check and keeps the in-context step', (id, phrase) => {
    const res = explain(id);
    expect(res.status).toBe(0);
    expect(res.stdout).not.toMatch(/Static analysis pattern finding\./);
    expect(res.stdout).toMatch(phrase);
    // Control for the step above: a live check still offers the scan.
    expect(nextSteps(res.stdout)).toMatch(/secure --verbose/);
  });
});
