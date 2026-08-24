/**
 * Structural tripwire (#523 follow-through): every render of a caught error's
 * `.message` in src/cli.ts either whole-string-escapes it on the printing
 * line or is the exact UsageError per-line idiom. The render-source gate
 * cannot see these sites (its PATH_NAME heuristic matches path-named
 * identifiers, not `message`), so without this test a raw catch-site render
 * ships on discipline alone.
 *
 * Scope, stated honestly: the predicate is line-based. A site that copies
 * `error.message` into a local and prints the local on another line evades
 * it, as does a reformat that splits the render across lines. It is a
 * tripwire against the observed failure mode — a raw `${error.message}`
 * inside a print call — not a taint analysis.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const src = readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
const lines = src.split('\n');

describe('error.message render idiom (src/cli.ts)', () => {
  it('every .message inside a print call is escaped on that line', () => {
    const offenders: string[] = [];
    lines.forEach((l, i) => {
      if (!(l.includes('console.error(') || l.includes('console.log(') || l.includes('console.warn(') || l.includes('process.stderr.write('))) return;
      if (!/\.message\b/.test(l)) return;
      if (l.includes('escapeForDisplay(')) return;
      offenders.push(`${i + 1}: ${l.trim()}`);
    });
    expect(offenders).toEqual([]);
  });

  it('every UsageError branch uses the per-line idiom', () => {
    const branches = (src.match(/instanceof UsageError/g) ?? []).length;
    expect(branches).toBeGreaterThanOrEqual(12);
    const idiom = /instanceof UsageError\) \{\s*\n\s*error\.message\.split\('\\n'\)\.forEach/g;
    expect((src.match(idiom) ?? []).length).toBe(branches);
  });

  it('message-family locals inside a print call are escaped on that line', () => {
    // ${msg} / ${message} / ${nMsg} ... — locals assigned from a caught
    // error's message and printed later. The RootRefusalError branch renders
    // its own refusal text raw BY DESIGN (multi-line ternary, every
    // interpolated path escaped where the message was built); its render
    // spans lines and so sits outside this line-based predicate, consistent
    // with the scope note above.
    const offenders: string[] = [];
    lines.forEach((l, i) => {
      if (!(l.includes('console.error(') || l.includes('console.log(') || l.includes('console.warn(') || l.includes('process.stderr.write('))) return;
      if (!/\$\{[A-Za-z]*[mM](sg|essage)\}/.test(l)) return;
      if (l.includes('escapeForDisplay(')) return;
      offenders.push(`${i + 1}: ${l.trim()}`);
    });
    expect(offenders).toEqual([]);
  });

  it('UsageError is never constructed here with raw interpolation', () => {
    // The tagged-template builder is the one allowed construction path; a
    // direct `new UsageError(...)` in cli.ts would bypass value escaping.
    expect((src.match(/new UsageError\(/g) ?? []).length).toBe(0);
  });

  it('shortenPath stayed deleted (#377)', () => {
    expect(src.includes('shortenPath')).toBe(false);
  });
});
