/**
 * #948 — the release record for DEP-001 on a tree with no package manifest
 * says the change is new in the release that carries it.
 *
 * 0.33.0 listed the MEDIUM lock-file advisory on a manifest-less tree under
 * Known issues, and 0.33.2 stated that it still fires (#751). 0.33.2 was cut
 * without the change that makes the package manifest the subject of DEP-001,
 * so no published version carries it, and the finding seen on 0.33.2 (#944) is
 * that known issue as published, not a fix that stopped working. The pending
 * entries held no record of the change at all: the next release would have
 * shipped it unannounced, with nothing to tell a reader of #751 or #944 which
 * version closes them, or that no earlier one did.
 *
 * The needle is the FIX wording. 0.33.0 and 0.33.2 both name DEP-001 while
 * describing the defect, so a bare `DEP-001` or `#751` finds one of those and
 * passes on a tree that never recorded the fix.
 */

import { describe, it, expect } from 'vitest';
import { sectionRecording, virtualChangelog } from '../helpers/changelog-record';

const CHANGELOG = virtualChangelog();

const RECORD = /^#### [^\n]*DEP-001[^\n]*not applicable[^\n]*#751/m;

/** The `####` entry that `RECORD` opens, up to the next heading of any level. */
function recordedEntry(): string {
  const section = sectionRecording(CHANGELOG, RECORD);
  const from = section.search(RECORD);
  const body = section.indexOf('\n', from) + 1;
  const next = section.slice(body).search(/^#{2,4} /m);
  const entry = next < 0 ? section.slice(from) : section.slice(from, body + next);
  expect(entry, 'the record is a title with no text under it').toMatch(/\n- /);
  return entry;
}

/** The released section for `version`, heading included. */
function releasedSection(version: string): string {
  const from = CHANGELOG.indexOf(`## [${version}]`);
  expect(from, `the ${version} heading is gone from CHANGELOG.md`).toBeGreaterThan(0);
  const next = CHANGELOG.slice(from + 1).search(/^## \[/m);
  return next < 0 ? CHANGELOG.slice(from) : CHANGELOG.slice(from, from + 1 + next);
}

describe('#948: the DEP-001 manifest-subject release record', () => {
  it('sits in a section newer than 0.33.2, and in none at or below it', () => {
    // Newest first: everything above the 0.33.2 heading is [Unreleased] or a
    // later release. The record stays there through every later release cut.
    const cut = CHANGELOG.indexOf('## [0.33.2]');
    expect(cut, 'the 0.33.2 heading is gone from CHANGELOG.md').toBeGreaterThan(0);
    expect(
      RECORD.test(CHANGELOG.slice(0, cut)),
      'no section newer than 0.33.2 records DEP-001 reading not applicable without a package.json',
    ).toBe(true);
    expect(
      RECORD.test(CHANGELOG.slice(cut)),
      '0.33.2 or an older section records the change, and none of them carried it',
    ).toBe(false);
  });

  it('names both issues and says no earlier version carried the change', () => {
    const entry = recordedEntry();
    for (const issue of ['#751', '#944']) {
      expect(entry, `the record does not name ${issue}`).toContain(issue);
    }
    expect(entry).toContain('This release is the first to carry the change');
    expect(entry).toContain('no published version');
    expect(entry, 'the record does not name the last version that shows the finding').toContain('0.33.2');
  });

  it('does not describe the change as a fix that came back', () => {
    // #944 read the finding on 0.33.2 as #751 regressing. A record worded that
    // way tells a reader that some earlier version was free of it.
    expect(recordedEntry()).not.toMatch(/regress|\bagain\b|\brestor|\breinstat|\breturn(s|ed|ing)?\b/i);
  });

  it('0.33.0 and 0.33.2 record the finding as present', () => {
    // What the wording rests on, read from the published sections themselves:
    // neither release closed the issue, so the next one is the first that does.
    expect(releasedSection('0.33.2')).toMatch(
      /`DEP-001` still fires on a tree without a `package\.json`\s*\(\[#751\]/,
    );
    expect(releasedSection('0.33.0')).toMatch(
      /### Known issues[\s\S]*`secure` reports `DEP-001` "No lock file found" \(MEDIUM\) on a tree that has\s+no package manifest at all/,
    );
  });
});
