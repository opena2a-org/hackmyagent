/**
 * CI guard for defect (9)'s laundering casts, extended per [CHIEF-CA]
 * 2026-08-21 (unit 2): no production file may cast a value INTO
 * `SecurityFinding` or `RedactedFinding` — the brand's one sanctioned cast
 * lives in `finding-emit.ts`, and every other spelling is a boundary bypass
 * the compiler cannot see.
 *
 * Scope is `src/` excluding `*.test.ts`: test files legitimately fabricate
 * finding-shaped fixtures (the pre-existing factories in
 * `src/registry/publish.test.ts` et al.), and the type system is not what a
 * test exercises. `as SecurityFindingDraft` is allowed everywhere — a draft
 * carries no guarantee to launder.
 *
 * This is a line-anchored text guard, with the known limits of one: it cannot
 * see a cast split across renames or an `as any` two-step. It exists as a
 * tripwire that forces classification, not as proof of absence — the runtime
 * reader (`assertRedactionProvenance`) is the layer that catches what text
 * cannot.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC_ROOT = join(__dirname, '..', '..', 'src');

/** The one file allowed to produce the brand (its single `as unknown as
 * RedactedFinding` at the end of `emitFinding`). */
const SANCTIONED = new Set(['hardening/finding-emit.ts']);

// `\b` after the type name: `SecurityFindingDraft` has no word boundary
// between "Finding" and "Draft", so draft casts do not match.
const LAUNDER_CAST = /\bas\s+(?:unknown\s+as\s+)?(?:SecurityFinding|RedactedFinding)\b(?:\[\])?/;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith('.ts') && !full.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

describe('finding cast-launder guard', () => {
  it('no production file casts into SecurityFinding or RedactedFinding', () => {
    const offenders: string[] = [];
    for (const file of walk(SRC_ROOT)) {
      const rel = file.slice(SRC_ROOT.length + 1);
      if (SANCTIONED.has(rel)) continue;
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        if (LAUNDER_CAST.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
      });
    }
    expect(offenders, 'launder casts found — route these through emitFinding/reemitFinding').toEqual([]);
  });

  it('positive control: the guard pattern actually matches a launder spelling', () => {
    // A regex that rots matches nothing and the empty-offenders assertion
    // above becomes vacuous. Pin the pattern against the spellings it exists
    // to catch, and against the draft spelling it must NOT catch.
    expect(LAUNDER_CAST.test('const f = bag as SecurityFinding;')).toBe(true);
    expect(LAUNDER_CAST.test('const f = bag as unknown as RedactedFinding;')).toBe(true);
    expect(LAUNDER_CAST.test('const f = bags as SecurityFinding[];')).toBe(true);
    expect(LAUNDER_CAST.test('const d = bag as SecurityFindingDraft;')).toBe(false);
  });

  it('positive control: the sanctioned file really contains the one brand cast', () => {
    // If finding-emit.ts is renamed or the cast moves, the exemption silently
    // exempts nothing — surface that instead of passing by accident.
    const content = readFileSync(join(SRC_ROOT, 'hardening', 'finding-emit.ts'), 'utf8');
    expect(LAUNDER_CAST.test(content)).toBe(true);
  });
});
