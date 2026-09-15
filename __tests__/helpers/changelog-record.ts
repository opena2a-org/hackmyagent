import { expect } from 'vitest';

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
