/**
 * #1004 — the release notes list the analyzer disagreement on a prose-written
 * role-play refusal under Known issues.
 *
 * `__tests__/soul/soul-corpus-direction.test.ts` pins the state: on the benign
 * corpus fixture `soul/benign/hardened-soul`, `scan-soul` exits 1 with
 * `SOUL-IH-003` as the one critical control not detected, while `secure` and
 * `check` pass the same directory. `docs/testing/release-smoke.md` tells the
 * person signing off a release to expect it. The pending entries said nothing:
 * no fragment of type `known-issue` existed, so the next release would have
 * announced its `scan-soul` changes and carried the disagreement unannounced.
 * 0.30.0 listed the `scan-soul` half once; no release since has.
 *
 * The needle is the entry's closing clause, a target version beside the issue
 * link. A later entry that records the fix names #1004 without a target, so it
 * cannot stand in for the known issue.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { sectionRecording, virtualChangelog } from '../helpers/changelog-record';

const REPO_ROOT = resolve(__dirname, '..', '..');
const CHANGELOG = virtualChangelog();
const DIRECTION_TEST = readFileSync(
  join(REPO_ROOT, '__tests__', 'soul', 'soul-corpus-direction.test.ts'),
  'utf-8',
);

const RECORD = /Target (\d+\.\d+\.\d+)\s*\(\[#1004\]\(/;

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

/** The newest Known-issues bullet whose subject, its first `#NNN`, is #1004. */
function knownIssueEntry(): string {
  const section = sectionRecording(CHANGELOG, RECORD);
  const entry = knownIssueBlocks(section)
    .flatMap(block => block.split(/^- /m).slice(1))
    .find(bullet => bullet.match(/#\d+/)?.[0] === '#1004');
  expect(entry, 'the #1004 record is not a bullet under a `### Known issues` heading').toBeDefined();
  return entry!;
}

function newer(a: string, b: string): boolean {
  const [x, y] = [a, b].map(v => v.split('.').map(Number));
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] > y[i];
  }
  return false;
}

describe('#1004: the SOUL-IH-003 prose-detection known issue', () => {
  it('is listed under Known issues in a section newer than 0.33.2', () => {
    // Newest first: everything above the 0.33.2 heading is [Unreleased] or a
    // later release. 0.33.2 shipped the state with no entry for it.
    const cut = CHANGELOG.indexOf('## [0.33.2]');
    expect(cut, 'the 0.33.2 heading is gone from CHANGELOG.md').toBeGreaterThan(0);
    expect(
      RECORD.test(CHANGELOG.slice(0, cut)),
      'no section newer than 0.33.2 lists the SOUL-IH-003 prose-detection disagreement with a target version',
    ).toBe(true);
    knownIssueEntry();
  });

  it('names the control, the three analyzers and the direction each one reports', () => {
    const entry = knownIssueEntry();
    expect(entry).toContain('`SOUL-IH-003`');
    for (const analyzer of ['`scan-soul`', '`secure <dir>`', '`check <dir> --nanomind`']) {
      expect(entry, `the entry does not name ${analyzer}`).toContain(analyzer);
    }
    expect(entry, 'the entry does not say scan-soul fails the file').toMatch(/Level\s+NONE,\s+and\s+exits\s+1/);
    expect(entry, 'the entry does not say the other two pass it').toMatch(/and\s+exit\s+0/);
    expect(entry, 'the entry does not say how the control is detected').toMatch(/keyword\s+match/);
  });

  it('targets a version newer than the release that carries the entry', () => {
    // A target equal to the carrying release promises a fix in the notes that
    // announce the defect. Under [Unreleased] the floor is the newest release.
    const section = sectionRecording(CHANGELOG, RECORD);
    const target = RECORD.exec(section)![1];
    const heading = section.split('\n')[0];
    const carrying = /^## \[(\d+\.\d+\.\d+)\]/.exec(heading)
      ?? /^## \[(\d+\.\d+\.\d+)\] - /m.exec(CHANGELOG);
    expect(carrying, 'the changelog carries no dated release heading').not.toBeNull();
    expect(
      newer(target, carrying![1]),
      `the entry targets ${target}, which is not newer than ${carrying![1]} (${heading})`,
    ).toBe(true);
  });

  it('describes a state the corpus direction test still pins', () => {
    // The entry and the pin move together. When SOUL-IH-003 reads the prose
    // form, that test changes, and this one fails until the known issue is
    // replaced by a record of the fix.
    expect(
      DIRECTION_TEST,
      'soul-corpus-direction.test.ts no longer pins SOUL-IH-003 as the one critical control '
        + 'not detected on the benign fixture: record the fix and retire the Known issues entry',
    ).toContain("expect(result.criticalMissing).toEqual(['SOUL-IH-003']);");
  });
});
