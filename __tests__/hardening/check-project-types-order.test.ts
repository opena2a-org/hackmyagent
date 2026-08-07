// `CHECK_PROJECT_TYPES` is resolved by FIRST match in declaration order, so a
// full check ID only overrides the group it belongs to while it is declared
// ABOVE that group. Nothing in the language enforces that: reordering the map,
// or a merge that reflows it, silently sends the specific key back to its
// group and removes a check from project types it was applying to.
//
// #421 rides on exactly this — `LOG-002` sits above `LOG-` so it applies
// everywhere while its advice-style siblings stay server-scoped. The
// alternative (resolve the longest key, no ordering dependency) was tried and
// reverted: two entries in the map are narrower than their group and had never
// taken effect, so activating them SUBTRACTED project types from unrelated
// checks — `SANDBOX-005` stopped applying to `webapp` and `api`.
//
// This asserts the ordering directly, and reports what a reorder would cost.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { findingAppliesTo } from '../../src/hardening/scanner';
import type { SecurityFinding, ProjectType } from '../../src/hardening/security-check';

const SOURCE = readFileSync(
  join(__dirname, '..', '..', 'src', 'hardening', 'scanner.ts'),
  'utf-8',
);

/** Declaration order of the map's keys, as written. */
function declaredKeys(): { key: string; types: string[] }[] {
  const start = SOURCE.indexOf('const CHECK_PROJECT_TYPES');
  expect(start, 'CHECK_PROJECT_TYPES not found — did it move or get renamed?')
    .toBeGreaterThan(-1);
  const block = SOURCE.slice(start, SOURCE.indexOf('\n};', start));
  const entries = [...block.matchAll(/^\s*'([A-Za-z0-9_-]+)':\s*\[([^\]]*)\]/gm)].map(m => ({
    key: m[1],
    types: m[2].replace(/[^a-z,]/g, '').split(',').filter(Boolean),
  }));
  // The parser is a regex over source. If the map grows a spelling it cannot
  // see (a double-quoted key, a multi-line array) that entry vanishes and every
  // assertion below passes vacuously for it. Pin the count so that fails loudly
  // rather than silently reducing coverage.
  expect(entries.length, 'parsed far fewer entries than the map holds — the parser missed a spelling')
    .toBeGreaterThanOrEqual(50);
  return entries;
}

function finding(checkId: string): SecurityFinding {
  return {
    checkId,
    name: 'synthetic',
    description: 'synthetic',
    category: 'synthetic',
    severity: 'high',
    passed: false,
    message: 'synthetic',
    fixable: false,
  };
}

const PROJECT_TYPES: ProjectType[] = [
  'cli', 'library', 'sdk', 'webapp', 'api', 'mcp', 'openclaw',
];

describe('CHECK_PROJECT_TYPES declaration order', () => {
  it('declares every full-ID override above the group it overrides', () => {
    const entries = declaredKeys();
    const misordered: string[] = [];
    entries.forEach((specific, si) => {
      entries.forEach((group, gi) => {
        if (specific.key === group.key) return;
        if (!specific.key.startsWith(group.key)) return;
        // `specific` is only reachable while it precedes `group`.
        if (gi < si) {
          misordered.push(
            `'${specific.key}' is declared AFTER its group '${group.key}', so it is unreachable ` +
            `and '${specific.key}' silently resolves to [${group.types.join(', ')}]`,
          );
        }
      });
    });
    // Entries that ARE unreachable today are listed explicitly rather than
    // asserted away, so adding a third one is a visible change.
    const KNOWN_UNREACHABLE = [
      "'SKILL-MEM-' is declared AFTER its group 'SKILL-'",
      "'SANDBOX-005' is declared AFTER its group 'SANDBOX-'",
    ];
    const unexpected = misordered.filter(
      m => !KNOWN_UNREACHABLE.some(k => m.startsWith(k)),
    );
    expect(unexpected, unexpected.join('\n')).toEqual([]);
  });

  // The consequence, asserted on behaviour rather than on the source text, so
  // the two cannot disagree.
  it('resolves LOG-002 ahead of the LOG- group', () => {
    for (const t of PROJECT_TYPES) {
      expect(findingAppliesTo(finding('LOG-002'), t), `LOG-002 must apply to ${t}`).toBe(true);
    }
    // Its siblings stay where they were, which is what proves the override is
    // the specific entry and not a widening of the group.
    expect(findingAppliesTo(finding('LOG-001'), 'library')).toBe(false);
    expect(findingAppliesTo(finding('LOG-003'), 'library')).toBe(false);
  });

  // A reorder that buries LOG-002 under LOG- is the regression this file
  // exists for; this states the cost in the failure message.
  it('keeps the two known-unreachable entries behaving as their group', () => {
    // If either of these ever becomes reachable, its own narrower list applies
    // and the check STOPS applying to project types it currently covers.
    expect(findingAppliesTo(finding('SANDBOX-005'), 'webapp')).toBe(true);
    expect(findingAppliesTo(finding('SANDBOX-005'), 'api')).toBe(true);
    expect(findingAppliesTo(finding('SKILL-MEM-001'), 'library')).toBe(true);
  });
});
