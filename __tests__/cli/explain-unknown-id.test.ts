/**
 * HMA-29 — `explain` must refuse an unknown check ID instead of printing a
 * generic prefix stub with exit 0.
 *
 * Measured on the pre-fix build (cebbc442): `explain NEMO-999` printed
 * "Static analysis pattern finding." — the prefixDescriptions branch, which
 * every hyphenated unknown whose prefix is in that table lands in — and
 * exited 0. A user asking about a typo'd or fabricated ID got a confident
 * non-answer and a green exit code a pipeline would wave through.
 *
 * AC1: an ID that is not in the check inventory — not a TAXONOMY_MAP key,
 *      not a static-explanations key, not a scan-soul CONTROL_DEFS id —
 *      exits non-zero, names the rejected ID, and suggests the nearest
 *      known IDs (shared-prefix or edit-distance neighbours).
 * AC2: the refusal misfires on nothing known — every ID the CLI already
 *      explains still produces an explanation with exit 0. The sweep below
 *      walks ALL THREE id sources (static explanations, CONTROL_DEFS,
 *      TAXONOMY_MAP), not a sample; spawn cells then pin exit 0 end-to-end
 *      for one representative of each resolution path, including an ID that
 *      resolves only through the attack-class lookup.
 *
 * Spawn cells follow the house pattern (redteam-unmeasured-exit.test.ts):
 * gated on the built CLI, dist-freshness asserted so a stale binary cannot
 * report a pass (#285). NANOMIND_URL is pinned to a dead local port so the
 * daemon probe fails as a fast local connection refusal and the static
 * explanation path is what's measured.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import {
  STATIC_EXPLANATIONS,
  PREFIX_DESCRIPTIONS,
  isKnownExplainId,
  suggestExplainIds,
} from '../../src/explain-registry';
import { getTaxonomyMap, getAttackClass } from '../../src/hardening/taxonomy';
import { CONTROL_DEFS } from '../../src/soul/scanner';

beforeAll(assertDistFreshIfPresent);

const DEAD_DAEMON = 'http://127.0.0.1:9';

function runExplain(id: string): { code: number | null; stdout: string; stderr: string } {
  const res = spawnSync(process.execPath, [CLI, 'explain', id], {
    encoding: 'utf-8',
    env: { ...process.env, NO_COLOR: '1', NANOMIND_URL: DEAD_DAEMON },
  });
  return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

describe.runIf(existsSync(CLI))('HMA-29.AC1 — explain refuses unknown check IDs (spawn)', () => {
  it('HMA-29.AC1 explain NEMO-999 exits non-zero, names the ID, and suggests neighbours', () => {
    const { code, stdout, stderr } = runExplain('NEMO-999');

    // The pre-fix behaviour this test was demonstrated RED against: the
    // generic prefix stub on stdout and exit 0.
    expect(stdout).not.toMatch(/Static analysis pattern finding\./);
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();

    // The refusal names the rejected ID …
    expect(stderr).toMatch(/NEMO-999/);
    // … and suggests nearest known IDs — shared-prefix neighbours for a
    // NEMO-prefixed unknown are the taxonomy's NEMO-0xx checks.
    expect(stderr).toMatch(/Did you mean/i);
    expect(stderr).toMatch(/NEMO-\d/);
  });

  it('HMA-29.AC1 an unknown ID with no known prefix also refuses with suggestions', () => {
    const { code, stderr } = runExplain('ZZZQ-123');
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();
    expect(stderr).toMatch(/ZZZQ-123/);
    // Even with no family match there are edit-distance neighbours to offer.
    expect(stderr).toMatch(/Did you mean/i);
  });

  it('HMA-29.AC1 the final-else unknown (unmapped prefix, no hyphen family) refuses too', () => {
    // Pre-fix this landed in the "may not be a valid check ID" branch — and
    // still exited 0. A message that says the ID may be invalid must not
    // carry a green exit code.
    const { code, stderr } = runExplain('NOTACHECK');
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();
    expect(stderr).toMatch(/NOTACHECK/);
  });
});

describe('HMA-29.AC2 — the refusal misfires on nothing known (all three id sources)', () => {
  // The three inventories the CLI explains from, enumerated in full. The
  // union feeds the predicate the CLI's refusal branch actually calls, so a
  // false refusal here is a false refusal in the binary.
  const staticIds = Object.keys(STATIC_EXPLANATIONS);
  const controlIds = CONTROL_DEFS.map((c) => c.id);
  const taxonomyIds = Object.keys(getTaxonomyMap());

  /**
   * Mirror of the explain action's rendering decision: which branch would
   * produce the explanation body for a known ID. 'none' is the dead
   * "No explanation available" branch — a known ID must never land there.
   */
  function explanationBranch(id: string): 'static' | 'soul-control' | 'attack-class' | 'none' {
    if (STATIC_EXPLANATIONS[id]) return 'static';
    if (CONTROL_DEFS.some((c) => c.id === id)) return 'soul-control';
    const prefix = id.split('-')[0];
    if (getAttackClass(id) || PREFIX_DESCRIPTIONS[prefix]) return 'attack-class';
    return 'none';
  }

  it('HMA-29.AC2 sweep: sources are non-empty (non-vacuity floor)', () => {
    expect(staticIds.length).toBeGreaterThan(20);
    expect(controlIds.length).toBeGreaterThan(50);
    expect(taxonomyIds.length).toBeGreaterThan(300);
  });

  it.each([
    ['static explanations table', staticIds],
    ['scan-soul CONTROL_DEFS', controlIds],
    ['TAXONOMY_MAP', taxonomyIds],
  ] as const)('HMA-29.AC2 every id in the %s is known and yields an explanation branch', (_source, ids) => {
    const refused = ids.filter((id) => !isKnownExplainId(id));
    expect(refused, `known ids the refusal would reject: ${refused.join(', ')}`).toEqual([]);

    const unexplained = ids.filter((id) => explanationBranch(id) === 'none');
    expect(
      unexplained,
      `known ids that would render "No explanation available": ${unexplained.join(', ')}`,
    ).toEqual([]);
  });

  it('HMA-29.AC2 suggestions never contain an unknown id', () => {
    for (const probe of ['NEMO-999', 'ZZZQ-123', 'SOUL-IH-999', 'CRED-01']) {
      for (const s of suggestExplainIds(probe)) {
        expect(isKnownExplainId(s), `suggested ${s} for ${probe} is itself unknown`).toBe(true);
      }
    }
  });
});

describe.runIf(existsSync(CLI))('HMA-29.AC2 — known IDs still explain with exit 0 (spawn, one per path)', () => {
  it.each([
    // static explanations table
    ['CRED-001', /Hardcoded credential/i],
    // CONTROL_DEFS only — SOUL-IH-003 is in neither the static table nor
    // TAXONOMY_MAP; it resolves through the governance catalog.
    ['SOUL-IH-003', /Role-play refusal/i],
    // taxonomy-only, prefix NOT in the category-label table: resolves only
    // through the attack-class lookup path (the AC2 callout).
    ['HEARTBEAT-001', /Attack class/i],
    // taxonomy + known prefix (the family NEMO-999 was impersonating).
    ['NEMO-001', /Attack class|finding/i],
  ] as const)('HMA-29.AC2 explain %s exits 0 and prints an explanation', (id, pattern) => {
    const { code, stdout, stderr } = runExplain(id);
    expect(stderr).not.toMatch(/Unknown check ID/i);
    expect(stdout).toMatch(pattern);
    expect(stdout).toMatch(id);
    expect(code).toBe(0);
  });
});
