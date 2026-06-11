import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { buildCheckOutput } from '@opena2a/check-core';

/**
 * check --json must carry the --nanomind advisory channel end-to-end.
 *
 * HMA computed analystEscalations/coverageSweep in every check path and then
 * dropped them at buildCheckOutput (check-core 0.2.0 had no carrier fields).
 * check-core 0.3.0 added the optional fields; this suite pins the wiring so
 * a future edit to a check path cannot silently drop the channel again.
 */

describe('check --json escalation wiring (check-core 0.3.0 adoption)', () => {
  it('every buildCheckOutput scan block in cli.ts passes analystEscalations + coverageSweep', () => {
    // Static wiring guard (deterministic, no network, no spawn): find each
    // buildCheckOutput call site and assert its scan{} block carries both
    // advisory fields. Same pattern as the concept-explainer reference test.
    const cli = readFileSync(join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
    const sites = [...cli.matchAll(/buildCheckOutput\(\{[\s\S]*?\n {6}\}\)\)/g)];
    expect(sites.length).toBeGreaterThanOrEqual(3); // github, pypi, npm paths
    for (const site of sites) {
      const block = site[0];
      expect(block, `buildCheckOutput site missing analystEscalations:\n${block}`).toContain(
        'analystEscalations',
      );
      expect(block, `buildCheckOutput site missing coverageSweep:\n${block}`).toContain(
        'coverageSweep',
      );
    }
  });

  it('pinned check-core emits the advisory fields after analystFindings, before narrative', () => {
    const out = buildCheckOutput({
      name: 'fixture-pkg',
      type: 'npm-package',
      scan: {
        projectType: 'library',
        score: 90,
        maxScore: 100,
        findings: [],
        analystFindings: [{ checkId: 'AST-X' }],
        analystEscalations: [{ file: 'docs/setup.html', routed: 'attack' }],
        coverageSweep: { candidates: 3, swept: 2, skipped: 1, nullVerdicts: 0, policy: 'abstention-gated' },
      },
      narrative: { summary: 'x' },
    });
    const keys = Object.keys(out);
    const idx = (k: string) => keys.indexOf(k);
    expect(out.analystEscalations).toEqual([{ file: 'docs/setup.html', routed: 'attack' }]);
    expect(out.coverageSweep).toEqual({
      candidates: 3, swept: 2, skipped: 1, nullVerdicts: 0, policy: 'abstention-gated',
    });
    expect(idx('analystFindings')).toBeLessThan(idx('analystEscalations'));
    expect(idx('analystEscalations')).toBeLessThan(idx('coverageSweep'));
    expect(idx('narrative')).toBe(keys.length - 1);
  });

  it('without --nanomind inputs the keys stay absent (parity contract)', () => {
    const out = buildCheckOutput({
      name: 'fixture-pkg',
      type: 'npm-package',
      scan: { projectType: 'library', score: 90, maxScore: 100, findings: [] },
    });
    expect('analystEscalations' in out).toBe(false);
    expect('coverageSweep' in out).toBe(false);
  });

  it('empty escalations are omitted but sweep accounting still emits', () => {
    const out = buildCheckOutput({
      name: 'fixture-pkg',
      type: 'npm-package',
      scan: {
        projectType: 'library',
        score: 90,
        maxScore: 100,
        findings: [],
        analystEscalations: [],
        coverageSweep: { candidates: 0, swept: 0, skipped: 0, nullVerdicts: 0, policy: 'abstention-gated' },
      },
    });
    expect('analystEscalations' in out).toBe(false);
    expect(out.coverageSweep).toBeDefined();
  });
});
