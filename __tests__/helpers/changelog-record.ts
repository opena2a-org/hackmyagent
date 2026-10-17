import { expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');
const PACKAGE_VERSION = (JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as { version: string }).version;
let virtualCache: string | undefined;

/**
 * CHANGELOG.md as a reader sees it with the pending entries included: the output
 * of `node scripts/changelog.mjs preview --virtual`.
 *
 * Unreleased entries are files under `changelog.d/` and CHANGELOG.md itself holds
 * only a pointer paragraph under `## [Unreleased]` until the release cut assembles
 * them. The virtual reading renders those files inside `## [Unreleased]`, so a
 * record is found by the same content before and after the cut. A failing script
 * (an invalid fragment, for one) fails every caller rather than reading as empty.
 */
export function virtualChangelog(): string {
  if (virtualCache === undefined) {
    virtualCache = execFileSync(
      process.execPath,
      [path.join(REPO_ROOT, 'scripts', 'changelog.mjs'), 'preview', '--virtual', '--changelog', path.join(REPO_ROOT, 'CHANGELOG.md')],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 1 << 26 },
    );
  }
  return virtualCache;
}

/**
 * The CHANGELOG.md section that records a change, found by its content.
 *
 * A record is written under `## [Unreleased]`, moves into a dated section at the
 * release cut, and every later release stacks a new section above it. A test that
 * pinned "the two newest sections" (the 2026-09-13 rewrite for 0.33.0) lost the
 * record at the very next cut (0.33.1), so the invariant now follows the record:
 * the newest `## [` section whose body matches `needle` is the recording section.
 * No match is an explicit failure, never a silent pass.
 */
export function sectionRecording(changelog: string, needle: RegExp | string): string {
  const hit = sections(changelog).find(s => matches(s, needle));
  expect(hit, `no CHANGELOG section records ${String(needle)}`).toBeDefined();
  return hit!;
}

/**
 * Every section from the newest down to and including the one that records the
 * change: the place to assert that a later release does not carry something the
 * recording section closed.
 */
export function sectionsThroughRecording(changelog: string, needle: RegExp | string): string {
  const all = sections(changelog);
  const idx = all.findIndex(s => matches(s, needle));
  expect(idx, `no CHANGELOG section records ${String(needle)}`).toBeGreaterThanOrEqual(0);
  return all.slice(0, idx + 1).join('');
}

/**
 * Asserts that `section`, the one `sectionRecording` found, sits where a record
 * can: under `## [Unreleased]` before the release cut, and after it under the
 * dated section of the version in package.json or of an older release. At the
 * cut that moves a record, the section of the version in package.json is the
 * newest heading; a test that accepted `[Unreleased]` alone lost its record at
 * the cut (the 0.34.0 cut moved three), and one that accepts the newest heading
 * alone loses it at the next cut, when the record keeps its section and a new
 * one stacks above it. A section newer than package.json is a release the tree
 * has not cut, so a record there is a defect, never a pass.
 */
export function expectRecordUnderUnreleasedOrRelease(section: string): void {
  const heading = section.split('\n')[0];
  if (heading === '## [Unreleased]') return;
  const release = /^## \[(\d+\.\d+\.\d+)\](?: - \d{4}-\d{2}-\d{2})?$/.exec(heading);
  expect(release, `the record sits under ${heading}, not under [Unreleased] or a release heading`).not.toBeNull();
  expect(
    compareVersions(release![1], PACKAGE_VERSION) <= 0,
    `the record sits under ${heading}, a release newer than package.json ${PACKAGE_VERSION}`,
  ).toBe(true);
}

function sections(changelog: string): string[] {
  return changelog.split(/^(?=## \[)/m).filter(s => s.startsWith('## ['));
}

/** Negative when `a` is the older release, zero when equal, positive when newer. */
function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

function matches(section: string, needle: RegExp | string): boolean {
  return typeof needle === 'string' ? section.includes(needle) : needle.test(section);
}
