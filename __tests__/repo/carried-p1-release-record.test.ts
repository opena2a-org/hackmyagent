/**
 * HMA-01.AC6 — the negative criterion: no third carry, no widened corroborator,
 * and the release record updated without publishing.
 *
 * Three properties, all checkable from the tree:
 *
 *   1. #368 and #390 are on their SECOND carry and the recorded rule is a
 *      maximum of two. No `Known issues` block from 0.30.0 — the release that
 *      closed them — onward may name either again. A third listing is the
 *      failure this criterion exists to catch, and it is the kind of thing that
 *      gets added by hand at release time, so it is pinned rather than trusted.
 *   2. The #475 execution-sink corroborator regexes are BYTE-IDENTICAL. The
 *      semantic half of #475 belongs to #424's AST dataflow unit; answering a
 *      semantic question with a wider lexical test would be the third instance
 *      of one mistake in this check. The claim "the regexes did not move" is
 *      only worth making if it can be diffed, so the exact bytes are pinned
 *      here as well as mirrored in `sink-corroborator-scope.test.ts`.
 *   3. `package.json` carries the LAST RELEASED version, and new work lands
 *      under `## [Unreleased]`. That is this repo's convention — the huge
 *      Unreleased section sitting above a `0.32.0` package version is what it
 *      looks like — and it is what keeps `hackmyagentVersion` in every JSON
 *      report from claiming a version that was never published. Publishing,
 *      tagging and cutting the dated section are the release seat's, not this
 *      unit's.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(__dirname, '..', '..');
const CHANGELOG = readFileSync(join(REPO_ROOT, 'CHANGELOG.md'), 'utf-8');
const SCANNER = readFileSync(join(REPO_ROOT, 'src', 'hardening', 'scanner.ts'), 'utf-8');
const PKG = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf-8')) as { version: string };

/** The Unreleased section, up to the first dated release heading. */
function unreleasedSection(): string {
  const start = CHANGELOG.indexOf('## [Unreleased]');
  expect(start, 'the changelog has no [Unreleased] section').toBeGreaterThanOrEqual(0);
  const next = CHANGELOG.indexOf('\n## [', start + 1);
  return next < 0 ? CHANGELOG.slice(start) : CHANGELOG.slice(start, next);
}

/** Every `### Known issues` block in `text`, body only. */
function knownIssueBlocks(text: string): string[] {
  const blocks: string[] = [];
  const heading = /^### Known issues.*$/gim;
  let m: RegExpExecArray | null;
  while ((m = heading.exec(text)) !== null) {
    const from = m.index + m[0].length;
    const nextHeading = text.slice(from).search(/^#{2,3} /m);
    blocks.push(nextHeading < 0 ? text.slice(from) : text.slice(from, from + nextHeading));
  }
  return blocks;
}

describe('HMA-01.AC6: no third carry, no widened corroborator, no publish', () => {
  it('HMA-01.AC6 no Known issues block from 0.30.0 onward names #368 or #390', () => {
    // 0.30.0 is where both were closed — `Findings are locatable, and their
    // Verify: commands run (#368, #286)` and `Breaking: scan-soul exit codes
    // now follow the conformance verdict (#390)`. Everything above it in this
    // newest-first file is 0.30.0 or later.
    const cut = CHANGELOG.indexOf('## [0.29.0]');
    expect(cut, 'the 0.29.0 heading moved — this slice no longer means what it says')
      .toBeGreaterThan(0);

    for (const block of knownIssueBlocks(CHANGELOG.slice(0, cut))) {
      for (const issue of ['#368', '#390']) {
        expect(
          block.includes(issue),
          `${issue} is on its third carry — the recorded rule is a maximum of two:\n${block.trim().slice(0, 400)}`,
        ).toBe(false);
      }
    }
  });

  it('HMA-01.AC6 the Unreleased section records the carried P1s as fixed', () => {
    // The other direction: a suite that only forbids a Known issues entry
    // passes on a release that says nothing about them at all.
    const unreleased = unreleasedSection();
    for (const issue of ['#368', '#477', '#478']) {
      expect(unreleased, `the Unreleased section does not name ${issue}`).toContain(issue);
    }
    expect(knownIssueBlocks(unreleased), 'the Unreleased section carries a Known issues block')
      .toHaveLength(0);
  });

  it('HMA-01.AC6 the #475 execution-sink corroborator regexes are byte-identical', () => {
    const open = SCANNER.indexOf('const EXECUTION_SINK_PATTERNS = [');
    expect(open, 'EXECUTION_SINK_PATTERNS is gone — the corroborator was restructured')
      .toBeGreaterThan(0);
    const close = SCANNER.indexOf('];', open);
    const body = SCANNER.slice(open, close + 2);

    // The two patterns this check has always carried, character for character.
    // `vm.runInNewContext`, `globalThis.eval`, `(0,eval)`, a constructor chain,
    // `Reflect.construct`, dynamic `import()`, `child_process` and
    // `module._compile` are still absent, deliberately (#424 owns that work).
    const lines = body
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.startsWith('/'));

    expect(lines).toEqual([
      String.raw`/(?:^|[^\w.$])eval\s*\(/,`,
      String.raw`/(?:^|[^\w.$])(?:new\s+)?Function\s*\(/,`,
    ]);
  });

  it('HMA-01.AC6 package.json carries the last released version, not an unpublished one', () => {
    const newestDated = /^## \[(\d+\.\d+\.\d+)\] - /m.exec(CHANGELOG);
    expect(newestDated, 'the changelog carries no dated release heading').not.toBeNull();
    expect(
      PKG.version,
      'package.json names a version with no dated changelog section — cutting the release '
        + 'and publishing belong to the release seat, not to a fix unit',
    ).toBe(newestDated![1]);
  });
});
