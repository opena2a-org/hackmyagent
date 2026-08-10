/**
 * The credential offset the compiler CARRIES, and the arithmetic that computes
 * it for a name-gated pattern (#368).
 *
 * `scanCanonicalCredentialFormats` has two loops with different offset rules,
 * and only one of them is trivial:
 *
 *   - the vendor-prefix loop matches the value itself, so `match.index` IS the
 *     value's offset;
 *   - the NAME-GATED loop matches `<name anchor><operator><value>` and captures
 *     only the value, so the value's offset is
 *     `match.index + match[0].length - value.length`.
 *
 * That second expression was the subtlest line added by #368 and nothing
 * exercised it: every credential fixture in the suite used a vendor prefix, so
 * replacing it with `match.index` left both suites green. The mutant is not
 * equivalent — it moves the offset to the start of the NAME, which changes the
 * masked evidence on every name-gated hit and the cited LINE on any hit whose
 * name and value are on different lines. The fixture below puts them on
 * different lines for exactly that reason.
 *
 * Run through the real compiler and the real analyzer rather than against the
 * scan helper alone: the offset only matters because two findings consume it,
 * and a test of the helper in isolation could stay green while the consumption
 * broke.
 */

import { describe, it, expect } from 'vitest';
import {
  SemanticCompiler,
  scanCanonicalCredentialFormatsForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeCredentials } from '../../src/nanomind-core/analyzers/credential-analyzer';
import type { SecurityAST } from '../../src/nanomind-core/types';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';

/**
 * 40 alphanumeric characters, high character diversity, no placeholder marker.
 *
 * Every constraint is a detector precondition, and each is asserted below
 * rather than assumed: `[A-Za-z0-9/+]{40}` is the pattern's value shape, a
 * value with 6 or fewer distinct characters is dropped as a redaction
 * sentinel, and FAKE/EXAMPLE/DUMMY/… anywhere in the bytes suppresses the hit.
 * A fixture that trips any of those makes this whole file vacuous, which is
 * why the shape is pinned in its own test.
 */
const VALUE = 'Ab7Kq2Zr9Xt4Nv6Mw1Ps3Cd8Hg5Jl0Ry2Uo4Ei6T';

/**
 * The name anchor sits on its own line and the value on the next. The regex's
 * `\s*` between the operator and the value spans the newline, so this is a
 * single match whose `index` and whose VALUE offset are on different lines —
 * the only fixture shape that can tell the two apart by line number.
 */
const CONTENT = [
  '// Deployment settings for the shipping worker.', // 1
  'export const region = "us-east-1";',              // 2
  '',                                                // 3
  'export const config = {',                         // 4
  '  awsSecretAccessKey:',                           // 5
  `    "${VALUE}",`,                                 // 6
  '};',                                              // 7
  '',
].join('\n');

/** Both derived from the fixture, never read back out of the code under test. */
const LINES = CONTENT.split('\n');
const ANCHOR_LINE = LINES.findIndex(l => l.includes('awsSecretAccessKey')) + 1;
const VALUE_LINE = LINES.findIndex(l => l.includes(VALUE)) + 1;

const PLACEHOLDER_MARKERS = [
  'FAKE', 'EXAMPLE', 'PLACEHOLDER', 'DUMMY', 'YOURKEY', 'YOUR_KEY',
  'YOURTOKEN', 'YOUR_TOKEN', 'REPLACE_ME', 'INSERT_HERE', 'SAMPLE', 'TEST', 'XXX',
];

describe('the fixture satisfies every name-gated detector precondition', () => {
  it('value shape, entropy, and marker-freedom', () => {
    expect(VALUE).toMatch(/^[A-Za-z0-9/+]{40}$/);
    // The low-entropy sentinel filter drops a value with <= 6 distinct chars.
    expect(new Set(VALUE).size).toBeGreaterThan(6);
    const upper = VALUE.toUpperCase();
    for (const marker of PLACEHOLDER_MARKERS) expect(upper).not.toContain(marker);
  });

  it('the name and the value are on DIFFERENT lines', () => {
    // The whole discriminating power of this file. If a reformat ever put them
    // on one line, `match.index` and the value offset would agree and the
    // mutation this file exists for would stop being observable.
    expect(ANCHOR_LINE).toBeGreaterThan(0);
    expect(VALUE_LINE).toBe(ANCHOR_LINE + 1);
    expect(LINES[ANCHOR_LINE - 1]).not.toContain(VALUE);
  });

  it('no VENDOR-prefix credential is present, so only the name-gated loop can fire', () => {
    // Non-vacuity against the other loop: a stray `sk-`/`ghp_`/`AKIA` in the
    // fixture would produce a hit whose offset arithmetic is the trivial one,
    // and the assertions below would pass without the line under test running.
    const hits = scanCanonicalCredentialFormatsForTest(CONTENT);
    expect(hits).toHaveLength(1);
    expect(hits[0].label).toBe('AWS secret access key');
  });
});

describe('the carried offset points at the VALUE, not at the name anchor (#368)', () => {
  // MUTATION: `index: match.index + match[0].length - value.length`
  //        -> `index: match.index`
  // Every assertion in this block must fail.

  it('the scan records the value"s own offset and length', () => {
    const [hit] = scanCanonicalCredentialFormatsForTest(CONTENT);
    // Derived from the fixture: the offset must slice back to exactly the
    // value. Under the mutant it slices the first 40 bytes of the match, which
    // begin with the name.
    expect(CONTENT.slice(hit.index, hit.index + hit.length)).toBe(VALUE);
    expect(hit.index).toBe(CONTENT.indexOf(VALUE));
    expect(hit.length).toBe(VALUE.length);
  });

  it('the risk surface carries it into the AST', async () => {
    const surfaces = (await compile()).inferredRiskSurface.filter(
      s => s.evidenceOffset !== undefined,
    );
    expect(surfaces).toHaveLength(1);
    expect(
      CONTENT.slice(surfaces[0].evidenceOffset!, surfaces[0].evidenceOffset! + surfaces[0].evidenceLength!),
    ).toBe(VALUE);
  });

  it('AST-CRED-001 cites the value"s line and masks the value, not the name', async () => {
    const cred = (await findingsFor()).find(f => f.checkId === 'AST-CRED-001');
    expect(cred, 'AST-CRED-001 must fire on the planted key').toBeDefined();
    expect(cred!.line).toBe(VALUE_LINE);
    expect(cred!.line).not.toBe(ANCHOR_LINE);
    // The evidence is masked from the SAME bytes the offset names, so under the
    // mutant it would read `  awsSecr…` — the variable name, presented to the
    // reader as the credential this CRITICAL is about.
    expect(cred!.evidence).toBe(`${VALUE.slice(0, 8)}${'*'.repeat(16)}`);
    expect(String(cred!.evidence)).not.toContain('aws');
  });

  it('AST-CRED-003 cites the same line', async () => {
    const cred = (await findingsFor()).find(f => f.checkId === 'AST-CRED-003');
    expect(cred, 'AST-CRED-003 must fire on the planted key').toBeDefined();
    expect(cred!.line).toBe(VALUE_LINE);
    expect(cred!.line).not.toBe(ANCHOR_LINE);
  });
});

/* ==================================================================
 * The VENDOR-PREFIX loop — the other half of the same arithmetic.
 *
 * The block above pins the name-gated loop, and its fixture deliberately
 * contains NO vendor credential so that loop cannot fire. That left
 * `index: match.index` (the vendor loop) asserted by nothing at all — and it
 * is the branch that actually fires on every `sk-`, `ghp_` and `AKIA` hit,
 * including both of the fixtures #368 was built on. Shifting it by one byte
 * kept the entire 3,755-test suite green.
 *
 * The mutant is NOT equivalent, and the damage is not cosmetic. The offset is
 * what `maskCredentialValue` slices, and it matches the vendor prefix against
 * the FIRST bytes of that slice. Shift by one and `sk-…` no longer matches a
 * known prefix, so masking falls through to the unknown-shape branch: the
 * CRITICAL's evidence stops being `sk-****…` and starts printing eight real
 * bytes of the key instead. A one-byte arithmetic slip becomes a disclosure.
 * ================================================================== */

/**
 * A vendor-prefixed value: the prefix is part of the credential itself.
 *
 * `sk-` plus 48 consecutive alphanumerics — the OpenAI legacy shape, whose
 * pattern is `sk-[a-zA-Z0-9]{48,}`. The count is a detector precondition, not
 * decoration: at 40 characters this fixture produced no hit at all and the
 * whole block below passed over an empty result set. Pinned in its own
 * assertion for that reason.
 */
const VENDOR_BODY = 'Ab7Kq2Zr9Xt4Nv6Mw1Ps3Cd8Hg5Jl0Ry2Uo4Ei6TVn3Bx5Qw';
const VENDOR_VALUE = `sk-${VENDOR_BODY}`;

const VENDOR_CONTENT = [
  '// Deployment settings for the billing worker.', // 1
  'export const region = "us-west-2";',             // 2
  '',                                               // 3
  `export const client = createClient("${VENDOR_VALUE}");`, // 4
  '',
].join('\n');

const VENDOR_LINES = VENDOR_CONTENT.split('\n');
const VENDOR_VALUE_LINE = VENDOR_LINES.findIndex(l => l.includes(VENDOR_VALUE)) + 1;

describe('the vendor fixture satisfies every precondition', () => {
  it('value shape, entropy, and marker-freedom', () => {
    // The shape the OpenAI legacy pattern requires. A body one character short
    // yields ZERO hits, which would make every assertion below vacuous.
    expect(VENDOR_BODY).toMatch(/^[a-zA-Z0-9]{48,}$/);
    expect(new Set(VENDOR_VALUE).size).toBeGreaterThan(6);
    const upper = VENDOR_VALUE.toUpperCase();
    for (const marker of PLACEHOLDER_MARKERS) expect(upper).not.toContain(marker);
  });

  it('exactly one hit, and it comes from the VENDOR loop', () => {
    // Non-vacuity against the other loop, mirrored: a name anchor in this
    // fixture would route the hit through the name-gated arithmetic instead,
    // and the assertions below would pass without the line under test running.
    const hits = scanCanonicalCredentialFormatsForTest(VENDOR_CONTENT);
    expect(hits).toHaveLength(1);
    expect(hits[0].label).not.toBe('AWS secret access key');
    // The value carries its own prefix, so the match IS the value — the
    // property that makes `match.index` the right answer here and the wrong
    // one in the name-gated loop.
    expect(VENDOR_VALUE.startsWith('sk-')).toBe(true);
  });

  it('the value does NOT start at the beginning of its line', () => {
    // Discriminating power: with the value at column 0 an off-by-one would
    // still slice inside the value and several assertions would survive.
    expect(VENDOR_LINES[VENDOR_VALUE_LINE - 1].indexOf(VENDOR_VALUE)).toBeGreaterThan(0);
  });
});

describe('the vendor loop records the value"s own first byte (#368)', () => {
  // MUTATION: `index: match.index` -> `index: match.index + 1`
  // (or any shift). Every assertion in this block must fail.

  it('the scan offset slices back to exactly the value', () => {
    const [hit] = scanCanonicalCredentialFormatsForTest(VENDOR_CONTENT);
    expect(VENDOR_CONTENT.slice(hit.index, hit.index + hit.length)).toBe(VENDOR_VALUE);
    expect(hit.index).toBe(VENDOR_CONTENT.indexOf(VENDOR_VALUE));
    expect(hit.length).toBe(VENDOR_VALUE.length);
  });

  it('the risk surface carries it into the AST', async () => {
    const surfaces = (await compileVendor()).inferredRiskSurface.filter(
      s => s.evidenceOffset !== undefined,
    );
    expect(surfaces).toHaveLength(1);
    expect(
      VENDOR_CONTENT.slice(
        surfaces[0].evidenceOffset!,
        surfaces[0].evidenceOffset! + surfaces[0].evidenceLength!,
      ),
    ).toBe(VENDOR_VALUE);
  });

  it('the masked evidence keeps the vendor prefix and leaks no key bytes', async () => {
    const cred = (await vendorFindingsFor()).find(f => f.checkId === 'AST-CRED-001');
    expect(cred, 'AST-CRED-001 must fire on the planted vendor key').toBeDefined();
    expect(cred!.line).toBe(VENDOR_VALUE_LINE);
    // Derived from the masking rule, not copied from output: prefix, then one
    // asterisk per remaining byte capped at 16.
    const remaining = Math.min(VENDOR_VALUE.length - 'sk-'.length, 16);
    expect(cred!.evidence).toBe(`sk-${'*'.repeat(remaining)}`);
    // The disclosure half, stated directly: under the shifted offset the
    // prefix match fails and eight real bytes of the key are printed.
    expect(String(cred!.evidence)).not.toContain(VENDOR_VALUE.slice(3, 11));
  });
});

/**
 * `app/deploy.ts`: a `source_code` path with no `test` / `fixture` / `example`
 * segment. Both are detector preconditions — the extension selects the
 * artifact type that runs the canonical scan at all, and any of those segments
 * suppresses the credential checks by design.
 */
async function compile(): Promise<SecurityAST> {
  const result = await new SemanticCompiler().compile(CONTENT, 'app/deploy.ts');
  if (!result.ast) throw new Error(`compile produced no AST: ${JSON.stringify(result.errors)}`);
  return result.ast;
}

async function findingsFor(): Promise<ASTFinding[]> {
  return analyzeCredentials(await compile(), () => true, undefined, CONTENT).filter(f => !f.passed);
}

async function compileVendor(): Promise<SecurityAST> {
  const result = await new SemanticCompiler().compile(VENDOR_CONTENT, 'app/billing.ts');
  if (!result.ast) throw new Error(`compile produced no AST: ${JSON.stringify(result.errors)}`);
  return result.ast;
}

async function vendorFindingsFor(): Promise<ASTFinding[]> {
  return analyzeCredentials(await compileVendor(), () => true, undefined, VENDOR_CONTENT)
    .filter(f => !f.passed);
}
