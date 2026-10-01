import { expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');
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

function sections(changelog: string): string[] {
  return changelog.split(/^(?=## \[)/m).filter(s => s.startsWith('## ['));
}

function matches(section: string, needle: RegExp | string): boolean {
  return typeof needle === 'string' ? section.includes(needle) : needle.test(section);
}
