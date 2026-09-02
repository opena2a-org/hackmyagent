/**
 * E4 — the enumeration guard.
 *
 * The credential vocabulary was copied into fourteen-plus places over time, and
 * every copy drifted: the redactor's hand-written body counts fell below the
 * detector's floor, so a token was DETECTED and then forwarded verbatim. The
 * registry makes the vocabulary enumerable. This test makes a NEW copy visible.
 *
 * It does not forbid a copy. It forbids a SILENT one: a new shape literal in a
 * file that is not on the frozen allowlist fails here, and the author has to
 * either take the shape from the registry or record, in the allowlist, why they
 * did not.
 *
 * The guard vocabulary is derived from `CREDENTIAL_SHAPES` on purpose, so a
 * shape added to the registry extends the guard in the same edit. The guards
 * themselves are pinned by hand in `credential-shape-fixtures.ts`, which is
 * what stops the guard being narrowed to see nothing.
 */
import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CREDENTIAL_SHAPES } from '../../src/types/credential-format';
import {
  scanForCredentialLiterals,
  UNOWNED_SHAPE_LITERALS,
  REGISTRY_FILES,
} from '../helpers/credential-literal-scan';

const REPO_ROOT = resolve(__dirname, '..', '..');

/**
 * Both trees that ship or gate behaviour. `scripts/` is included because
 * `scripts/release-smoke-corpus.ts` already reads finding evidence text and is
 * the pre-publish gate — a shape table growing there would be exactly as
 * invisible as one in `src`, and it currently carries none.
 */
const SCAN_ROOTS = [join(REPO_ROOT, 'src'), join(REPO_ROOT, 'scripts')];

function scan(literals: readonly string[]): {
  counts: Record<string, number>;
  witnesses: Record<string, readonly string[]>;
} {
  const counts: Record<string, number> = {};
  const witnesses: Record<string, readonly string[]> = {};
  for (const root of SCAN_ROOTS) {
    const r = scanForCredentialLiterals(REPO_ROOT, root, literals);
    Object.assign(counts, r.counts);
    Object.assign(witnesses, r.witnesses);
  }
  return { counts, witnesses };
}

/**
 * THE FROZEN ALLOWLIST.
 *
 * Measured on `main` at `9a6fbc8` (published 0.31.0) by this file's own
 * scanner, over the guard literals this file's own registry declares — so the
 * baseline and the check are the same code path, which is the property the
 * previous baseline lacked.
 *
 * That previous baseline — "17 files / 251 literals, scanner.ts alone has 49" —
 * is real and re-runnable (its `rg` command reproduces exactly: 17 files, 251
 * occurrences, 49 scanner.ts LINES), but it counts a different vocabulary: a
 * hand-written pattern list that no code consumes, so a shape added to the
 * registry does not extend it. The numbers here are lower for `src` and higher
 * in coverage: per-file rather than per-tree, occurrences rather than lines,
 * and derived from the registry. Both stand; they measure different things.
 *
 * Each entry is a file that carries a hand-written copy of a credential shape
 * TODAY, with the number of guard-literal occurrences in it. The counts are
 * ceilings. Adoption work is expected to drive them DOWN; nothing here may
 * drive them up.
 *
 * The two large entries are the two the adoption step exists to remove:
 * `scanner.ts` (95) holds four disagreeing shape tables, and
 * `credential-analyzer.ts` (46) plus `defense-in-depth.ts` (27) plus
 * `build-narrative.ts` (26) are the masking and redaction copies.
 */
const FROZEN_ALLOWLIST: Readonly<Record<string, number>> = {
  'src/attack/payloads/a2a-attacks.ts': 2,
  'src/attack/payloads/data-exfiltration.ts': 1,
  'src/attack/payloads/mcp-exploitation.ts': 1,
  'src/attack/payloads/memory-weaponization.ts': 1,
  'src/attack/scanner.ts': 1,
  'src/benchmarks/oasb-1.ts': 2,
  'src/cli.ts': 4,
  'src/hardening/coverage-ledger.ts': 2,
  'src/hardening/nemoclaw-scanner.ts': 1,
  // 95 -> 96 when v0.32.0 merged into main. The 96th is NOT code: #533 added a
  // doc comment describing its fixture, "(an `sk-ant-api03` shaped key,
  // `child_process.exec`, and a curl-pipe-to-sh)". The counter is deliberately
  // blind to comment-vs-code so it cannot be evaded, so a prose mention lands
  // here. Verified as the only delta: v0.32.0's copy of this file counts 95 and
  // main's counts 96, and `git log -S'sk-ant'` attributes the difference to
  // a51bdfb alone.
  'src/hardening/scanner.ts': 96,
  'src/nanomind-core/analyzers/credential-analyzer.ts': 46,
  'src/nanomind-core/compiler/semantic-compiler.ts': 32,
  'src/nanomind-core/compiler/source-code-preprocessor.ts': 3,
  'src/nanomind-core/ingestion/artifact-parser.ts': 6,
  // 27 -> 28 in HMA-34. The counter is blind to what a literal is FOR, and the
  // fail-closed `pem-private-key` rule states its own invariant with a negative
  // lookahead — the body may not cross another armor header — so the ruled
  // pattern spells the `-----BEGIN` guard token twice, once in the header and
  // once inside the lookahead that stops the body at the next armor header.
  // No new vocabulary was added: it
  // is the same token the rule already carried, now load-bearing twice. Nothing
  // else in the file moved.
  'src/nanomind-core/security/defense-in-depth.ts': 28,
  'src/narrative/build-narrative.ts': 26,
  'src/plugins/credvault.ts': 10,
  'src/plugins/signcrypt.ts': 1,
  'src/scanner/external-scanner.ts': 6,
  'src/scanner/permission-vocabulary.ts': 13,
  'src/semantic/structural/credential-context.ts': 15,
  'src/semantic/structural/mcp-config.ts': 6,
};

// 302 -> 303 in HMA-34, the single +1 from `defense-in-depth.ts` above.
const FROZEN_TOTAL = 303;

function guardLiterals(): string[] {
  return [...CREDENTIAL_SHAPES.flatMap(s => [...s.guards]), ...UNOWNED_SHAPE_LITERALS];
}

describe('E4 — credential vocabulary enumeration guard', () => {
  it('the frozen total is the sum of the frozen entries', () => {
    // Guards the constant against a copy-paste edit that updates one and not
    // the other, which would make the total assertion below vacuous.
    expect(Object.values(FROZEN_ALLOWLIST).reduce((a, b) => a + b, 0)).toBe(FROZEN_TOTAL);
  });

  it('no file outside the frozen allowlist carries a credential shape literal', () => {
    const { counts, witnesses } = scan(guardLiterals());
    const unlisted = Object.keys(counts)
      .filter(f => !(f in FROZEN_ALLOWLIST))
      .map(f => `${f} (${witnesses[f].join(' ')})`);
    expect(
      unlisted,
      'A new credential shape literal appeared outside the registry. Take the shape from ' +
        'CREDENTIAL_SHAPES, or add the file to FROZEN_ALLOWLIST with the reason it cannot.',
    ).toEqual([]);
  });

  it('no allowlisted file grows', () => {
    const { counts, witnesses } = scan(guardLiterals());
    const grown = Object.keys(FROZEN_ALLOWLIST)
      .filter(f => (counts[f] ?? 0) > FROZEN_ALLOWLIST[f])
      .map(f => `${f}: ${FROZEN_ALLOWLIST[f]} -> ${counts[f]} (${witnesses[f]?.join(' ')})`);
    expect(grown, 'A file gained credential shape literals.').toEqual([]);
  });

  it('the total never grows', () => {
    const { counts } = scan(guardLiterals());
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    expect(total).toBeLessThanOrEqual(FROZEN_TOTAL);
  });

  it('every allowlisted file still exists', () => {
    // A renamed file would otherwise appear as a new file (caught above) while
    // its stale entry silently kept a budget alive for a path nobody reads.
    const gone = Object.keys(FROZEN_ALLOWLIST).filter(f => !existsSync(join(REPO_ROOT, f)));
    expect(gone).toEqual([]);
  });

  it('the guard vocabulary is derived from the registry, not hand-listed here', () => {
    const literals = guardLiterals();
    const fromRegistry = CREDENTIAL_SHAPES.flatMap(s => [...s.guards]);
    expect(literals.slice(0, fromRegistry.length)).toEqual(fromRegistry);
    expect(literals.length).toBe(fromRegistry.length + UNOWNED_SHAPE_LITERALS.length);
  });

  it('both trees are scanned, and scripts/ carries no shape literal today', () => {
    expect(SCAN_ROOTS.map(r => r.replace(REPO_ROOT + '/', ''))).toEqual(['src', 'scripts']);
    const scriptsOnly = scanForCredentialLiterals(
      REPO_ROOT,
      join(REPO_ROOT, 'scripts'),
      guardLiterals(),
    );
    expect(Object.keys(scriptsOnly.counts)).toEqual([]);
  });

  it('the registry file is the only exclusion', () => {
    expect(REGISTRY_FILES).toEqual(['src/types/credential-format.ts']);
    expect(existsSync(join(REPO_ROOT, REGISTRY_FILES[0]))).toBe(true);
  });

  it('the scanner actually finds literals — a guard that finds nothing proves nothing', () => {
    // Non-vacuity. If the walk broke, every assertion above would pass on an
    // empty result set, which is the failure mode this whole file exists to
    // prevent one level up.
    const { counts } = scan(guardLiterals());
    expect(Object.keys(counts).length).toBeGreaterThanOrEqual(20);
    expect(counts['src/hardening/scanner.ts']).toBeGreaterThan(50);
  });

  it('the two unowned literals are each carried by exactly one file', () => {
    // Shape literals in `src` that no detector in the tree knows about. If a
    // second file picks one up, that is a new vocabulary and this reds.
    expect(
      Object.keys(scan(['ghr_']).counts),
    ).toEqual(['src/scanner/permission-vocabulary.ts']);
    expect(
      Object.keys(scan(['nvapi-']).counts),
    ).toEqual(['src/hardening/nemoclaw-scanner.ts']);
    for (const literal of UNOWNED_SHAPE_LITERALS) {
      expect(CREDENTIAL_SHAPES.some(s => s.guards.includes(literal)), literal).toBe(false);
    }
  });
});
