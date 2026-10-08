/**
 * #452 — `secure -f sarif` emits one rule descriptor per rule, and every
 * result points at its rule by `ruleIndex`.
 *
 * `tool.driver.rules` was built one descriptor per RESULT, so a check that
 * fired twice produced two identical descriptors. SARIF 2.1.0 declares
 * `rules` `uniqueItems`, so the document validated only on targets where
 * every check fired once: 117 descriptors for 50 rule ids on the malicious
 * corpus fixture (0.26.1 and 0.27.0), which GitHub's SARIF upload rejects.
 * The fixture here makes one check fire in two files, the smallest tree that
 * reproduces it.
 */
import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');
const FAKE_GH_TOKEN = `ghp_${'d'.repeat(36)}`;
let dir: string | undefined;

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

interface Sarif {
  runs: Array<{
    tool: { driver: { rules: Array<{ id: string }> } };
    results: Array<{ ruleId: string; ruleIndex?: number }>;
  }>;
}

describe('#452 SARIF rule table', () => {
  let rules: Sarif['runs'][number]['tool']['driver']['rules'] = [];
  let results: Sarif['runs'][number]['results'] = [];

  // #909 — the fixture and the scan belong in a hook. vitest runs a describe
  // body while it collects the file, so a scan written there ran under
  // `vitest list`, which runs no test, and under an empty HOME downloaded the
  // classifier model. It also ran before the freshness hook above.
  // The hook's own limit sits above the spawn's (vitest.config.ts explains
  // why a cap below the spawn budget only mislabels a slow scan).
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'hma-sarif-rules-'));
    writeFileSync(join(dir, 'package.json'), '{"name":"sarif-fixture","version":"1.0.0"}\n');
    mkdirSync(join(dir, 'config'));
    writeFileSync(join(dir, 'config', 'production.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    writeFileSync(join(dir, 'config', 'staging.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    const run = spawnSync('node', [CLI, 'secure', dir, '-f', 'sarif'], {
      encoding: 'utf8', timeout: 180_000, env: { ...process.env, NO_COLOR: '1' },
    });
    const sarif = JSON.parse(run.stdout) as Sarif;
    ({ rules } = sarif.runs[0].tool.driver);
    ({ results } = sarif.runs[0]);
  }, 200_000);

  it('has a check that fired more than once (non-vacuity)', () => {
    const counts = new Map<string, number>();
    for (const r of results) counts.set(r.ruleId, (counts.get(r.ruleId) ?? 0) + 1);
    expect([...counts.values()].some(n => n > 1), `no repeated ruleId in ${JSON.stringify([...counts])}`).toBe(true);
  });

  it('emits each rule id once', () => {
    const ids = rules.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    // uniqueItems compares whole descriptors; unique ids imply it.
    expect(new Set(rules.map(r => JSON.stringify(r))).size).toBe(rules.length);
  });

  it('points every result at its rule by ruleIndex', () => {
    for (const r of results) {
      expect(r.ruleIndex, `result ${r.ruleId} carries no ruleIndex`).toBeTypeOf('number');
      expect(rules[r.ruleIndex!].id).toBe(r.ruleId);
    }
  });

  it('has a rule for every result and no rule without one', () => {
    expect(new Set(rules.map(r => r.id))).toEqual(new Set(results.map(r => r.ruleId)));
  });
});
