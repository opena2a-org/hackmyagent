/**
 * WHICH offset-carrying risk surface the credential citation selects (#368).
 *
 * `locatedCredentialRisk` originally returned the FIRST `CRED-HARVEST` surface
 * carrying an offset. Two things make "first" the wrong choice, and neither is
 * visible from the fixtures that motivated the carry:
 *
 *   1. **Surfaces are pushed in `CANONICAL_CREDENTIAL_PATTERNS` order, not file
 *      order.** `AWS access key` is index 3 and `GitHub personal access token`
 *      is index 4, so a file with a GitHub token on line 2 and an AWS key on
 *      line 5 pushes the AWS surface first and cites line 5. The citation then
 *      depends on the order a pattern list happens to be written in.
 *   2. **The canonical scan and the GATE match different sets.** The gate is
 *      `findCredentialFormatMatch`; the canonical scan is the offset producer.
 *      `PEM private key` matches only the header MARKER
 *      (`-----BEGIN RSA PRIVATE KEY-----`), which the gate does not accept and
 *      which contains no key material. A file holding that marker as an
 *      ordinary string constant — a PEM sniffing helper — got the citation
 *      moved onto it and off the real credential that fired the finding.
 *
 * Case 2 is the one that inverts the module's whole purpose: pre-#368 the
 * citation named the real token, and the carry moved it to a harmless
 * constant, with a `Verify:` command that prints something innocuous. That is
 * `src/types/finding-location.ts`'s "a citation that is confidently wrong is
 * worse than an absent one", produced by the change that quotes it.
 *
 * THE RULE THESE PIN: among offset-carrying surfaces, consider only those whose
 * bytes the GATE also accepts, and take the LEFTMOST of those. Where none
 * qualifies the citation falls back to the gate's own leftmost match, which is
 * exactly the pre-#368 behaviour — so this can never be worse than main.
 *
 * The third block is the negative control and it matters as much as the other
 * two: it is the case #368 exists to fix, and a "fix" that simply stopped
 * consuming the carried offset would pass blocks 1 and 2 and fail this one.
 */

import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeCredentials } from '../../src/nanomind-core/analyzers/credential-analyzer';
import { hasCredentialFormat } from '../../src/types/credential-format';
import type { SecurityAST } from '../../src/nanomind-core/types';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';

/**
 * Values are built from fixed high-diversity alphabets rather than a literal
 * key: the detectors drop a value with too few distinct characters as a
 * redaction sentinel, and any FAKE/EXAMPLE/DUMMY segment suppresses the hit
 * outright. Each precondition is asserted below rather than assumed.
 */
/**
 * EXACTLY 36 characters after `ghp_`. The canonical pattern is
 * `ghp_[a-zA-Z0-9]{36}` — a 32-character body is accepted by the GATE (whose
 * width is `{20,}`) but not by the canonical scan, so it produces no offset
 * surface and the ordering case silently stops being tested. The width is
 * asserted below rather than trusted.
 */
const GH_TOKEN = 'ghp_' + 'aB3kQ9zR7tN2vM6wP1sC8dH5gJ0lYx4UeT7v';
const HF_TOKEN = 'hf_' + 'Kq7Zr2Xt9Nv4Mw6Ps1Cd3Hg8Jl5Ry0Uo';
const AWS_KEY = 'AKIA' + 'Q7ZR2XT9NV4MW6PS';
const SK_KEY = 'sk-' + 'Ab7Kq2Zr9Xt4Nv6Mw1Ps3Cd8Hg5Jl0Ry2Uo4Ei6Tz3Wn5Bv7';

/** A real SHA-256 digest: 64 hex chars, no vendor prefix. */
const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** The PEM header marker, as a source file would hold it for a prefix check. */
const PEM_MARKER = '-----BEGIN RSA PRIVATE KEY-----';

// ── 1. Pattern-list order must not decide the citation ──────────────────────
//
// GitHub token line 2, AWS key line 5. AWS is the LOWER pattern index, so a
// first-with-an-offset selection cites line 5.
const ORDER_CONTENT = [
  '// Integration credentials.',              // 1
  `const githubToken = "${GH_TOKEN}";`,       // 2
  '',                                         // 3
  '// Storage.',                              // 4
  `const awsAccessKeyId = "${AWS_KEY}";`,     // 5
  'module.exports = { githubToken, awsAccessKeyId };', // 6
].join('\n');
const ORDER_GH_LINE = 2;
const ORDER_AWS_LINE = 5;

// ── 2. A gate-rejected marker must not take the citation ────────────────────
const PEM_CONTENT = [
  '// PEM sniffing helper. Holds no key material.', // 1
  `const PEM_HEADER = "${PEM_MARKER}";`,            // 2
  'function isPem(s) { return s.startsWith(PEM_HEADER); }', // 3
  '',                                                // 4
  `const hfToken = "${HF_TOKEN}";`,                  // 5
  'module.exports = { isPem, hfToken };',            // 6
].join('\n');
const PEM_MARKER_LINE = 2;
const PEM_TOKEN_LINE = 5;

// ── 3. Negative control: the case the carry exists for ──────────────────────
//
// A digest ABOVE the real key. The gate's leftmost match is the digest (it is a
// credible entropy blob); the canonical scan matches only the vendor-prefixed
// key. The carry is what moves the citation to the key, and it must survive.
const DIGEST_CONTENT = [
  '// Build metadata.',                  // 1
  `const buildSha = "${DIGEST}";`,       // 2
  '',                                    // 3
  '// Service configuration.',           // 4
  `const openaiKey = "${SK_KEY}";`,      // 5
  'module.exports = { buildSha, openaiKey };', // 6
].join('\n');
const DIGEST_LINE = 2;
const DIGEST_KEY_LINE = 5;

describe('the fixtures satisfy their detector preconditions', () => {
  it('the GitHub token is the exact width the CANONICAL scan requires', () => {
    // Gate width and canonical width differ (`{20,}` vs `{36}`). A fixture that
    // only satisfies the gate produces no offset surface, and the ordering
    // block below then passes for the wrong reason.
    expect(GH_TOKEN.slice('ghp_'.length)).toHaveLength(36);
  });

  it('the gate ACCEPTS every planted credential value', () => {
    for (const v of [GH_TOKEN, HF_TOKEN, AWS_KEY, SK_KEY]) {
      expect(hasCredentialFormat(v), `gate must accept ${v.slice(0, 6)}…`).toBe(true);
    }
  });

  it('the gate REJECTS the PEM marker, which is what makes case 2 a defect', () => {
    // If this ever flips, the PEM fixture stops testing the gate-disagreement
    // case and this file must be rebuilt rather than re-pinned.
    expect(hasCredentialFormat(PEM_MARKER)).toBe(false);
  });

  it('the planted values sit on the lines the assertions name', () => {
    expect(ORDER_CONTENT.split('\n')[ORDER_GH_LINE - 1]).toContain(GH_TOKEN);
    expect(ORDER_CONTENT.split('\n')[ORDER_AWS_LINE - 1]).toContain(AWS_KEY);
    expect(PEM_CONTENT.split('\n')[PEM_MARKER_LINE - 1]).toContain(PEM_MARKER);
    expect(PEM_CONTENT.split('\n')[PEM_TOKEN_LINE - 1]).toContain(HF_TOKEN);
    expect(DIGEST_CONTENT.split('\n')[DIGEST_LINE - 1]).toContain(DIGEST);
    expect(DIGEST_CONTENT.split('\n')[DIGEST_KEY_LINE - 1]).toContain(SK_KEY);
  });

  it('the AWS surface really is pushed before the GitHub one', async () => {
    // The premise of case 1. Asserted from the AST rather than from the pattern
    // table, so it fails loudly if the push order ever changes and the fixture
    // silently stops exercising the ordering bug.
    const offsets = (await compile(ORDER_CONTENT, 'app/integrations.ts'))
      .inferredRiskSurface
      .filter(s => s.attackClass === 'CRED-HARVEST' && s.evidenceOffset !== undefined)
      .map(s => s.evidenceOffset!);
    expect(offsets.length, 'both credentials must produce an offset surface').toBe(2);
    expect(offsets[0], 'AWS (later in file) must be pushed first').toBeGreaterThan(offsets[1]);
  });
});

describe('the citation is the LEFTMOST gate-accepted surface, not the first pushed (#368)', () => {
  it('AST-CRED-001 cites the GitHub token on line 2, not the AWS key on line 5', async () => {
    const f = await finding(ORDER_CONTENT, 'app/integrations.ts', 'AST-CRED-001');
    expect(f.line).toBe(ORDER_GH_LINE);
    expect(f.line).not.toBe(ORDER_AWS_LINE);
  });

  it('the masked evidence names the value on the cited line', async () => {
    const f = await finding(ORDER_CONTENT, 'app/integrations.ts', 'AST-CRED-001');
    // Derived from the fixture, not copied from the output: the evidence must
    // be the mask of the GitHub token, so a citation that moved would carry
    // the wrong prefix and fail here as well as on the line.
    expect(f.evidence).toContain(GH_TOKEN.slice(0, 4));
    expect(String(f.evidence)).not.toContain(AWS_KEY.slice(0, 4));
  });

  it('AST-CRED-003 cites the same line as AST-CRED-001', async () => {
    const one = await finding(ORDER_CONTENT, 'app/integrations.ts', 'AST-CRED-001');
    const three = await finding(ORDER_CONTENT, 'app/integrations.ts', 'AST-CRED-003');
    expect(three.line).toBe(one.line);
  });
});

describe('a gate-rejected marker never takes the citation (#368)', () => {
  it('AST-CRED-001 cites the hf_ token, not the PEM header constant', async () => {
    const f = await finding(PEM_CONTENT, 'app/pem.ts', 'AST-CRED-001');
    expect(f.line).toBe(PEM_TOKEN_LINE);
    expect(f.line, 'citing the PEM marker points the reader at a harmless constant')
      .not.toBe(PEM_MARKER_LINE);
  });

  it('AST-CRED-003 does not acquire a wrong line where it previously had none', async () => {
    const f = await finding(PEM_CONTENT, 'app/pem.ts', 'AST-CRED-003');
    // The pre-#368 behaviour here was NO line, which is honest. Anything other
    // than the real token's line is a manufactured citation.
    if (f.line !== undefined) expect(f.line).toBe(PEM_TOKEN_LINE);
    expect(f.line).not.toBe(PEM_MARKER_LINE);
  });
});

describe('NEGATIVE CONTROL: the carry still beats the gate on the digest case (#368)', () => {
  // If a fix removed the carried offset instead of fixing its selection, every
  // assertion above would still pass and this block would fail.
  it('AST-CRED-001 cites the sk- key on line 5, not the digest on line 2', async () => {
    const f = await finding(DIGEST_CONTENT, 'app/config.ts', 'AST-CRED-001');
    expect(f.line).toBe(DIGEST_KEY_LINE);
    expect(f.line, 'the leftmost GATE match is the digest — the carry is what beats it')
      .not.toBe(DIGEST_LINE);
  });

  it('AST-CRED-003 cites the key line too', async () => {
    const f = await finding(DIGEST_CONTENT, 'app/config.ts', 'AST-CRED-003');
    expect(f.line).toBe(DIGEST_KEY_LINE);
  });
});

describe('the offset bounds check, on BOTH sides of each boundary (#368)', () => {
  /**
   * A real compiled AST whose credential surface offset is then overwritten.
   * The compiler cannot be made to emit an out-of-range offset, and a
   * hand-built AST would be a different object from the one production uses —
   * so the shape stays real and only the two numbers move.
   *
   * The guard is a BOUNDS check, not an integrity check: `signAST` does not
   * cover `inferredRiskSurface`, so nothing here can be described as detecting
   * tampering. What it prevents is slicing outside the buffer.
   */
  async function citeWithOffset(
    start: number,
    length: number,
  ): Promise<number | undefined> {
    const ast = await compile(DIGEST_CONTENT, 'app/config.ts');
    for (const s of ast.inferredRiskSurface) {
      if (s.attackClass === 'CRED-HARVEST' && s.evidenceOffset !== undefined) {
        s.evidenceOffset = start;
        s.evidenceLength = length;
      }
    }
    return analyzeCredentials(ast, () => true, undefined, DIGEST_CONTENT)
      .filter(f => !f.passed)
      .find(f => f.checkId === 'AST-CRED-001')?.line;
  }

  /** The exact offset/length the compiler recorded for the planted key. */
  async function realSpan(): Promise<{ start: number; length: number }> {
    const ast = await compile(DIGEST_CONTENT, 'app/config.ts');
    const s = ast.inferredRiskSurface.find(
      r => r.attackClass === 'CRED-HARVEST' && r.evidenceOffset !== undefined,
    );
    if (!s) throw new Error('no offset-carrying surface — fixture no longer reaches the guard');
    return { start: s.evidenceOffset!, length: s.evidenceLength! };
  }

  it('ACCEPTS a span ending exactly at content.length', async () => {
    // The inclusive edge. A guard written `>=` instead of `>` would refuse a
    // credential that happens to end the file, and no other case in this block
    // catches that — the two refusal cases below would both still pass.
    // The content is built so the last bytes ARE the credential.
    const content = DIGEST_CONTENT + '\n' + SK_KEY;
    expect(content.endsWith(SK_KEY), 'the span under test must end the buffer').toBe(true);
    const ast = await compile(content, 'app/config.ts');
    for (const s of ast.inferredRiskSurface) {
      if (s.attackClass === 'CRED-HARVEST' && s.evidenceOffset !== undefined) {
        s.evidenceOffset = content.length - SK_KEY.length;
        s.evidenceLength = SK_KEY.length;
      }
    }
    const line = analyzeCredentials(ast, () => true, undefined, content)
      .filter(f => !f.passed)
      .find(f => f.checkId === 'AST-CRED-001')?.line;
    expect(line).toBe(content.split('\n').length);
  });

  it('REFUSES a span one byte past the end, and falls back rather than throwing', async () => {
    const { start } = await realSpan();
    const line = await citeWithOffset(start, DIGEST_CONTENT.length - start + 1);
    // Falls back to the gate's leftmost match, which on this fixture is the
    // digest. The point is that it neither throws nor cites from a clamped
    // slice.
    expect(line).toBe(DIGEST_LINE);
  });

  it('REFUSES a negative start', async () => {
    expect(await citeWithOffset(-1, 8)).toBe(DIGEST_LINE);
  });

  it('REFUSES a zero length', async () => {
    const { start } = await realSpan();
    expect(await citeWithOffset(start, 0)).toBe(DIGEST_LINE);
  });
});

async function compile(content: string, file: string): Promise<SecurityAST> {
  const result = await new SemanticCompiler().compile(content, file);
  if (!result.ast) throw new Error(`compile produced no AST: ${JSON.stringify(result.errors)}`);
  return result.ast;
}

async function finding(content: string, file: string, checkId: string): Promise<ASTFinding> {
  const ast = await compile(content, file);
  const found = analyzeCredentials(ast, () => true, undefined, content)
    .filter(f => !f.passed)
    .find(f => f.checkId === checkId);
  if (!found) throw new Error(`${checkId} did not fire on ${file} — fixture no longer reaches the branch under test`);
  return found;
}
