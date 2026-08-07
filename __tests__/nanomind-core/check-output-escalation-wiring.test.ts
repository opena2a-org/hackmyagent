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

/**
 * Every `buildCheckOutput({ ... })` argument in a source file, delimited by
 * brace balance rather than by indentation.
 *
 * The previous matcher was `/buildCheckOutput\(\{[\s\S]*?\n {6}\}\)\)/g` — it
 * anchored on a closing brace at exactly six spaces followed by `))`. Wrapping
 * the three call sites to add `coverage` (#416) indented them by two and
 * changed the tail from `))` to `}),`, and the guard responded by matching
 * two sites instead of three and passing on the two. A source gate that goes
 * quiet when the source is reformatted is not a gate; counting braces is
 * indentation-independent and cannot silently narrow its own scope.
 */
function buildCheckOutputArgs(source: string): string[] {
  const blocks: string[] = [];
  const marker = 'buildCheckOutput({';
  for (let i = source.indexOf(marker); i !== -1; i = source.indexOf(marker, i + 1)) {
    let depth = 0;
    for (let j = i + marker.length - 1; j < source.length; j++) {
      if (source[j] === '{') depth++;
      else if (source[j] === '}') {
        depth--;
        if (depth === 0) { blocks.push(source.slice(i, j + 1)); break; }
      }
    }
  }
  return blocks;
}

describe('check --json escalation wiring (check-core 0.3.0 adoption)', () => {
  it('every buildCheckOutput scan block in cli.ts passes analystEscalations + coverageSweep', () => {
    // Static wiring guard (deterministic, no network, no spawn): find each
    // buildCheckOutput call site and assert its scan{} block carries both
    // advisory fields. Same pattern as the concept-explainer reference test.
    const cli = readFileSync(join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
    const sites = buildCheckOutputArgs(cli);
    expect(sites.length).toBeGreaterThanOrEqual(3); // github, pypi, npm paths
    for (const site of sites) {
      const block = site;
      expect(block, `buildCheckOutput site missing analystEscalations:\n${block}`).toContain(
        'analystEscalations',
      );
      expect(block, `buildCheckOutput site missing coverageSweep:\n${block}`).toContain(
        'coverageSweep',
      );
    }
  });

  it('the site matcher finds a call site whatever its indentation', () => {
    // Red-proof for the matcher itself. The bug it replaces was invisible
    // because the guard still passed on a subset; this asserts the count, and
    // asserts it survives the reformatting that broke the regex.
    const flat = 'writeJsonStdout(buildCheckOutput({ name: "a", scan: {} }));';
    const nested = [
      '      writeJsonStdout({',
      '        ...buildCheckOutput({',
      '          name: "b",',
      '          scan: { findings: [] },',
      '        }),',
      '        coverage: coverageJson(v),',
      '      });',
    ].join('\n');
    expect(buildCheckOutputArgs(flat)).toHaveLength(1);
    expect(buildCheckOutputArgs(nested)).toHaveLength(1);
    expect(buildCheckOutputArgs(`${flat}\n${nested}`)).toHaveLength(2);
    expect(buildCheckOutputArgs('no call sites here')).toHaveLength(0);
    // And it captures the whole argument, not a prefix of it.
    expect(buildCheckOutputArgs(nested)[0]).toContain('findings');
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
