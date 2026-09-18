/**
 * #446 — the `secure --deep` simulation verdict is a measurement, or it is not
 * printed. The release record must say so, and the text-search path it
 * replaces must be gone from the tree.
 *
 * The needle is the FIX wording, not a bare `#446`: the issue is carried as a
 * Known-issues entry in two older sections (0.32.0, 0.33.0), so a bare needle
 * finds one of those and passes on a tree that never recorded the fix.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { sectionRecording, sectionsThroughRecording } from '../helpers/changelog-record';

const REPO_ROOT = resolve(__dirname, '..', '..');
const CHANGELOG = readFileSync(join(REPO_ROOT, 'CHANGELOG.md'), 'utf-8');
const ENGINE = readFileSync(join(REPO_ROOT, 'src', 'simulation', 'engine.ts'), 'utf-8');

const RECORD = /NOT MEASURED[^\n]*#446|#446[^\n]*NOT MEASURED/;

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

describe('#446 release record', () => {
  it('records the fix under [Unreleased] or the newest dated section', () => {
    const section = sectionRecording(CHANGELOG, RECORD);
    const newestDated = /^## \[(\d+\.\d+\.\d+)\] - /m.exec(CHANGELOG);
    expect(newestDated, 'the changelog carries no dated release heading').not.toBeNull();
    const heading = section.split('\n')[0];
    expect(
      heading === '## [Unreleased]' || heading.startsWith(`## [${newestDated![1]}]`),
      `the #446 record sits under ${heading}, not under [Unreleased] or the newest release`,
    ).toBe(true);
    // The record names the line the channel now prints and the count it prints with an executor.
    expect(section).toContain('no probe executor');
    expect(section).toContain('advisory, not');
  });

  it('carries no Known-issues entry keyed on #446 from the newest section through the recording one', () => {
    // A carry is a Known-issues ENTRY whose subject is the issue: the bullet's
    // first `#NNN`. A later bullet may reference #446 while describing its own
    // defect; a bare includes() cannot tell the two apart.
    for (const block of knownIssueBlocks(sectionsThroughRecording(CHANGELOG, RECORD))) {
      const bullets = block.split(/^- /m).slice(1);
      for (const bullet of bullets) {
        const subject = bullet.match(/#\d+/)?.[0];
        expect(
          subject === '#446',
          `a Known issues entry keyed on #446 at or above the section that records the fix:\n${bullet.trim().slice(0, 400)}`,
        ).toBe(false);
      }
    }
  });

  it('the engine carries no text-search probe evaluator', () => {
    // The verdict the record describes was computed by this function from the
    // artifact's own wording. Its absence is the whole fix; a re-added fallback
    // under the same name would bring the defect back.
    expect(ENGINE).not.toContain('evaluateProbeHeuristic');
    expect(ENGINE).toContain("verdict: 'NOT_MEASURED'");
  });
});
