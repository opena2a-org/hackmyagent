/**
 * #360 — the `+ N more` line names where the FOLDED findings are.
 */
import { describe, it, expect } from 'vitest';
import { collapsedLocation, MAX_NAMED_FILES } from '../../src/ui/collapse-label';

describe('collapsedLocation (#360)', () => {
  it('names the one file every folded finding is in', () => {
    expect(collapsedLocation(['lib/cbom.mjs', 'lib/cbom.mjs'])).toBe(' in cbom.mjs');
  });

  it('names the folded files, never the printed finding\'s file', () => {
    // The #360 shape: printed lib/cbom.mjs, folded two siblings.
    expect(collapsedLocation(['lib/scanner-tls.mjs', 'lib/scanner.mjs'])).toBe(' in scanner-tls.mjs, scanner.mjs');
  });

  it('lists each file once, in report order', () => {
    expect(collapsedLocation(['lib/b.js', 'lib/a.js', 'lib/b.js'])).toBe(' in b.js, a.js');
  });

  it('counts the files once there are more than it lists', () => {
    const files = Array.from({ length: MAX_NAMED_FILES + 1 }, (_, n) => `lib/f${n}.js`);
    expect(collapsedLocation(files)).toBe(` in ${MAX_NAMED_FILES + 1} files`);
    expect(collapsedLocation(files.slice(0, MAX_NAMED_FILES))).toBe(` in ${files.slice(0, MAX_NAMED_FILES).map((f) => f.slice(4)).join(', ')}`);
  });

  it('claims no location when a folded finding has no file', () => {
    expect(collapsedLocation(['a.js', undefined])).toBe('');
    expect(collapsedLocation([undefined])).toBe('');
    expect(collapsedLocation([])).toBe('');
  });

  it('escapes a scanned name before it reaches the terminal', () => {
    const out = collapsedLocation(['lib/x\x1b[2Jy.js']);
    expect(out).not.toContain('\x1b');
    expect(out.startsWith(' in ')).toBe(true);
  });
});
