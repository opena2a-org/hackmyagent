/**
 * HMA-31 — the sink corroborator's string-literal predicate lexes regex
 * literals (shape a of the ruling), so a same-line regex no longer downgrades
 * a UNICODE-STEGO-002 decoder from CRITICAL to MEDIUM.
 *
 * The defect: `isMatchInsideStringLiteral` counted quote characters and its
 * own doc comment said it did not attempt to detect regex literals, so the
 * apostrophe in `const re = /['"]/; eval(buildPayload());` opened phantom
 * quote state and the `eval` token answered "inside a string". Severity is
 * `corroborated ? 'critical' : 'medium'` and MEDIUM exits 0, so one zero-cost
 * line beside the sink walked a live decoder past a CI gate.
 *
 * Also closed here, as ruled:
 *  - N1 (HMA-31.AC3): `eval` and `(` separated by a newline corroborate again.
 *    The two per-line patterns stay byte-identical; the trailing sink token is
 *    carried across the line boundary as state.
 *  - N2 (HMA-31.AC4): a line over MAX_LINE_LENGTH is still skipped — removing
 *    the bound reopens the minified-bundle false positive — but the
 *    uncorroborated message now names the skipped line and says why it was
 *    not read.
 *
 * Second revision of the lexer, addressing the findings below:
 *  - AC7: keyword-spelled property and method names are identifiers —
 *    `stats.in / stats.out` and `obj.if(y) / 2` are divisions, not regex
 *    openers.
 *  - AC8: postfix `++`/`--` and non-ASCII identifiers decide division; the
 *    fallback for an unlisted punctuator is the ruled opener set, not "any
 *    other punctuator opens a regex".
 *  - AC9: comment blanking is regex-aware — `//` or `/*` inside a regex
 *    literal's body is regex text, not a comment opener.
 *  - AC10: the undecidable-slash walk is paid once per line, so a crafted
 *    line cannot amplify the corroborator's per-mention predicate calls.
 *
 * Same discipline as sink-corroborator-scope.test.ts: no invisible codepoint
 * is written anywhere in this file, and every suppression case is paired with
 * a case that must still reach CRITICAL.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner, isMatchInsideStringLiteral } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

/** Mirrors `MAX_LINE_LENGTH` in `src/hardening/scanner.ts`, which is module-private. */
const MAX_LINE_LENGTH = 10000;

/** The corroborator, character for character as the scanner carries it (HMA-31.AC6). */
const SINK_PATTERNS = [
  /(?:^|[^\w.$])eval\s*\(/,
  /(?:^|[^\w.$])(?:new\s+)?Function\s*\(/,
];

/** The decoder shape of sink-corroborator-scope.test.ts:57-66, verbatim. */
const DECODER_SHAPE = [
  'function read(input) {',
  '  const out = [];',
  '  for (let i = 0; i < input.length; i++) {',
  '    const cp = input.codePointAt(i);',
  '    if (cp >= 0xFE00 && cp <= 0xFE0F) out.push(cp - 0xFE00);',
  '  }',
  '  return out;',
  '}',
];

const SCANNER_SOURCE = path.join(__dirname, '..', '..', 'src', 'hardening', 'scanner.ts');

describe('HMA-31.AC2: the predicate lexes regex literals under the shape-(a) rules', () => {
  it('HMA-31.AC2 a same-line regex before eval no longer reads as an open quote (deciding shape A)', () => {
    const line = `const re = /['"]/; eval(buildPayload());`;
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC2 a regex after an if-guarded paren group opens as a regex (shape B)', () => {
    const line = `if (x) /['"]/.test(s); eval(p)`;
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it("HMA-31.AC2 the old doc comment's own example /won't/; eval(payload) is real code", () => {
    const line = `/won't/; eval(payload)`;
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC2 a slash after a value is division, not a regex opener (control, false on both sides)', () => {
    const line = `const half = n / 2; const s = 'a'; eval(p)`;
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC2 the detection-rule label string beside a regex literal is still a string (true on both sides)', () => {
    const line = String.raw`  { pattern: /eval\s*\(/, label: 'eval() dynamic execution' },`;
    const idx = line.indexOf('eval() dynamic');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(true);
  });

  it('HMA-31.AC2 past six undecidable slashes the lexer stops branching and fails toward corroboration', () => {
    // Seven `}` `/'/` sequences: each slash follows `}`, so each is an
    // undecidable point. The seventh is past the budget of six; the helper
    // must stop branching and answer "not inside" even though the quote
    // parity of the line would say otherwise.
    const line = "} /'/ ".repeat(7) + 'eval(p)';
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC2 the predicate doc comment no longer disclaims regex lexing', async () => {
    const source = await fs.readFile(SCANNER_SOURCE, 'utf-8');
    expect(source).not.toContain('does NOT attempt to detect regex literals');
  });
});

describe('HMA-31.AC7/AC8: keyword-spelled names and unlisted punctuators, at the predicate level', () => {
  it('HMA-31.AC7 a keyword-spelled property name does not open a regex', () => {
    const line = 'x = a.in / b; eval(p)';
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC7 a keyword-spelled method call decides division after its closing paren', () => {
    const line = 'const r = obj.if(y) / 2; eval(p)';
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC8 postfix ++ before a slash decides division, not a regex opener', () => {
    const line = 'let h = i++ / 2; eval(p)';
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC8 a non-ASCII identifier is a word, so the slash after it is division', () => {
    const line = 'const t = groß / 2; eval(p)';
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });
});

describe('HMA-31: the corroborator end to end', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-sink-lexer-'));
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({ name: 'sink-lexer-project', version: '1.0.0' })
    );
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  async function stego002For(file: string): Promise<SecurityFinding[]> {
    const result = await scanner.scan({ targetDir: tempDir });
    return result.findings.filter(
      (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === file
    );
  }

  /** Same non-vacuity guard as sink-corroborator-scope.test.ts. */
  function expectFixtureStillTriggersTheOldReader(content: string): void {
    expect(content).toContain('.codePointAt(');
    expect(content).toMatch(/0x(?:FE0|E010)/);
    expect(
      SINK_PATTERNS.some((p) => p.test(content)),
      'the fixture no longer matches the sink regexes, so this measures nothing'
    ).toBe(true);
  }

  it('HMA-31.AC1 a same-line regex literal no longer downgrades the decoder to MEDIUM', async () => {
    // The deciding case: the attacker's zero-cost, behaviour-preserving
    // arrangement. At base this reported MEDIUM (exit 0) because the
    // apostrophe inside the regex class toggled the quote walker.
    const content = [
      ...DECODER_SHAPE,
      `const re = /['"]/; eval(buildPayload());`,
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'same-line-regex.js'), content);

    const findings = await stego002For('same-line-regex.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC1 the control with the regex on the previous line stays CRITICAL', async () => {
    // Identical content, one newline moved. CRITICAL on both sides of the fix.
    const content = [
      ...DECODER_SHAPE,
      `const re = /['"]/;`,
      `eval(buildPayload());`,
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'prev-line-regex.js'), content);

    const findings = await stego002For('prev-line-regex.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC3 eval split from its paren by a newline corroborates', async () => {
    const content = [
      ...DECODER_SHAPE,
      'eval',
      '(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'newline-eval.js'), content);

    const findings = await stego002For('newline-eval.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC3 new Function split from its paren by a newline corroborates', async () => {
    const content = [
      ...DECODER_SHAPE,
      'const build = new Function',
      "('return payload');",
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'newline-function.js'), content);

    const findings = await stego002For('newline-function.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC3 a trailing eval not followed by an opening paren stays uncorroborated', async () => {
    // Non-vacuity direction for the carry: the state must corroborate only
    // when the next code line actually opens the call.
    const content = [
      ...DECODER_SHAPE,
      'const alias = eval',
      'run(alias);',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'trailing-eval-no-paren.js'), content);

    const findings = await stego002For('trailing-eval-no-paren.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].message).toContain('uncorroborated');
  });

  it('HMA-31.AC3 a trailing eval inside a multi-line template stays uncorroborated', async () => {
    // The line ends with the token `eval`, but inside an unterminated
    // template literal — a mention, not a call, even though the next line
    // opens with `(`.
    const content = [
      ...DECODER_SHAPE,
      'const s = `do not eval',
      '(anything) from here`;',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'template-trailing-eval.js'), content);

    const findings = await stego002For('template-trailing-eval.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].message).toContain('uncorroborated');
  });

  it('HMA-31.AC4 a sink on an over-length line stays MEDIUM but the message names the skipped line', async () => {
    // The bound is KEPT: removing it reopens the minified-bundle false
    // positive it was introduced for. What changes is disclosure — the
    // uncorroborated message names the line it did not read, and why.
    const bundle = `const BUNDLE = "${'a'.repeat(MAX_LINE_LENGTH)}";eval(BUNDLE);`;
    expect(bundle.length).toBeGreaterThan(MAX_LINE_LENGTH);
    const content = [...DECODER_SHAPE, bundle].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'named-skipped-line.js'), content);

    const findings = await stego002For('named-skipped-line.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(['critical', 'high']).not.toContain(findings[0].severity);
    expect(findings[0].message).toContain('uncorroborated');
    // The bundle sits after the 8 decoder-shape lines: 1-based line 9.
    expect(findings[0].message).toContain('line 9');
    expect(findings[0].message).toMatch(/not read/);
    expect(findings[0].message).toMatch(/per-line limit/);
  });

  it('HMA-31.AC5 an eval( inside a genuine string literal beside a same-line regex does not corroborate', async () => {
    const content = [
      ...DECODER_SHAPE,
      `const re = /['"]/; const s = 'eval(payload)'; run(s);`,
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'string-beside-regex.js'), content);

    const findings = await stego002For('string-beside-regex.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].message).toContain('uncorroborated');
  });

  it('HMA-31.AC7 a keyword-spelled property name (.in) beside a division no longer downgrades the decoder', async () => {
    const content = [
      ...DECODER_SHAPE,
      'const r = stats.in / stats.out; eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'property-in.js'), content);

    const findings = await stego002For('property-in.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC7 a keyword-spelled property name (.new) beside a division no longer downgrades the decoder', async () => {
    const content = [
      ...DECODER_SHAPE,
      'const r = counts.new / counts.total; eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'property-new.js'), content);

    const findings = await stego002For('property-new.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC7 a keyword-spelled method call (obj.if) beside a division no longer downgrades the decoder', async () => {
    const content = [
      ...DECODER_SHAPE,
      'const r = obj.if(y) / 2; eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'method-if.js'), content);

    const findings = await stego002For('method-if.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC8 postfix ++ before a division no longer downgrades the decoder', async () => {
    const content = [
      ...DECODER_SHAPE,
      'let i = 0; const h = i++ / 2; eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'postfix-increment.js'), content);

    const findings = await stego002For('postfix-increment.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC8 a non-ASCII identifier before a division no longer downgrades the decoder', async () => {
    const content = [
      ...DECODER_SHAPE,
      'const t = π / 2; eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'non-ascii-identifier.js'), content);

    const findings = await stego002For('non-ascii-identifier.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC9 a regex literal whose body spells // does not open a phantom line comment', async () => {
    const content = [
      ...DECODER_SHAPE,
      String.raw`const u = /^https?:\/\//; eval(buildPayload());`,
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'url-regex.js'), content);

    const findings = await stego002For('url-regex.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC9 a regex literal whose body spells /* does not open a phantom block comment', async () => {
    const content = [
      ...DECODER_SHAPE,
      String.raw`const clean = s.replace(/\/*$/, '');`,
      'eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'strip-slash-regex.js'), content);

    const findings = await stego002For('strip-slash-regex.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC9 the phantom block comment does not swallow a sink four lines later either', async () => {
    const content = [
      ...DECODER_SHAPE,
      String.raw`const clean = s.replace(/\/*$/, '');`,
      'const a = 1;',
      'const b = 2;',
      'const c = 3;',
      'eval(buildPayload());',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'strip-slash-regex-later.js'), content);

    const findings = await stego002For('strip-slash-regex-later.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-31.AC3 the cross-line carry resets at a skipped over-length line', async () => {
    // The over-length branch `continue`d before the
    // pending-token check, so a trailing `eval` leaked across the skipped
    // line and corroborated an IIFE that is not its call.
    const content = [
      ...DECODER_SHAPE,
      'const a = eval',
      'x'.repeat(MAX_LINE_LENGTH + 1),
      '(function(){})();',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'carry-across-skipped.js'), content);

    const findings = await stego002For('carry-across-skipped.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].message).toContain('uncorroborated');
  });
});

describe('HMA-31.AC10: the undecidable-slash walk cannot be amplified by a crafted line', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-sink-amplify-'));
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({ name: 'sink-amplify-project', version: '1.0.0' })
    );
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  /**
   * The amplification line: six undecidable fork points, then 800 string
   * mentions of eval — every mention used to re-run the full forked walk
   * (base 29 ms → 1005 ms for one line with the earlier per-mention walk;
   * 137 ms → 9293 ms for ten).
   */
  const AMPLIFIER = '} /a/ '.repeat(6) + "'eval(p)' + ".repeat(800) + '0;';

  it('HMA-31.AC10 one amplification line scans within the pinned bound', async () => {
    await fs.writeFile(path.join(tempDir, 'amplifier.js'), AMPLIFIER);
    const t0 = performance.now();
    await scanner.scan({ targetDir: tempDir });
    // Generous against the fix (~tens of ms), red against the earlier
    // per-mention walk, measured at 1005 ms.
    expect(performance.now() - t0).toBeLessThan(750);
  });

  it('HMA-31.AC10 ten amplification lines scan within the pinned bound', async () => {
    await fs.writeFile(
      path.join(tempDir, 'amplifier10.js'),
      Array(10).fill(AMPLIFIER).join('\n')
    );
    const t0 = performance.now();
    await scanner.scan({ targetDir: tempDir });
    // Generous against the fix, red against the earlier per-mention walk,
    // measured at 9293 ms.
    expect(performance.now() - t0).toBeLessThan(2500);
  });

  it('HMA-31.AC10 six undecidable points with the sink in a string still agree on suppression', () => {
    // The discriminating pair: with `/a/` bodies the
    // honest lexings of every path agree the eval mention is inside the
    // trailing string, so at six points — within budget — the answer is
    // "inside". At a budget of 100 the seven-point line below would answer
    // the same; only the ruled budget makes it differ.
    const line = '} /a/ '.repeat(6) + "'eval(p)'";
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(true);
  });

  it('HMA-31.AC10 the seventh undecidable point hits the budget and fails toward corroboration', () => {
    const line = '} /a/ '.repeat(7) + "'eval(p)'";
    const idx = line.indexOf('eval(');
    expect(idx).toBeGreaterThan(0);
    expect(isMatchInsideStringLiteral(line, idx)).toBe(false);
  });

  it('HMA-31.AC9 the blanker doc no longer claims a phantom quote can only blank less', async () => {
    const source = await fs.readFile(SCANNER_SOURCE, 'utf-8');
    // The earlier wording wrapped mid-phrase ("blank less, not\n * more"), so pin
    // the fragment that survives the wrap.
    expect(source).not.toContain('blank less');
  });
});

describe('HMA-31.AC6: nothing outside the ruling moves', () => {
  it('HMA-31.AC6 the ruled surfaces of scanner.ts are unmoved at the delivered commit', async () => {
    const source = await fs.readFile(SCANNER_SOURCE, 'utf-8');

    // The severity expression is untouched.
    expect(source).toContain("severity: corroborated ? 'critical' : 'medium',");

    // The two sink patterns are byte-identical and remain the ONLY entries:
    // no new sink vocabulary (vm, globalThis.eval, Reflect.construct,
    // import(), child_process stay out).
    const block = /const EXECUTION_SINK_PATTERNS = \[([\s\S]*?)\];/.exec(source);
    expect(block).not.toBeNull();
    const entries = block![1]
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    expect(entries).toEqual([
      String.raw`/(?:^|[^\w.$])eval\s*\(/,`,
      String.raw`/(?:^|[^\w.$])(?:new\s+)?Function\s*\(/,`,
    ]);

    // The per-line bound is kept.
    expect(source).toContain('const MAX_LINE_LENGTH = 10000');

    // The cross-line carry (HMA-31.AC3) names the same two tokens as the
    // patterns above and nothing else — diff-pinned so a new sink cannot
    // enter through it.
    expect(source).toContain(
      String.raw`const TRAILING_SINK_TOKEN = /(?:^|[^\w.$])((?:new\s+)?Function|eval)\s*$/;`
    );

    // The predicate remains the corroborator's decision path (#424 untouched:
    // no AST route replaces it here).
    expect(source).toContain('export function isMatchInsideStringLiteral');
    expect(source).toContain('if (!isMatchInsideStringLiteral(codeLine, tokenIndex))');

    // The N1 disclosure that called the newline spelling undetected is gone
    // from the scanner and from the changelog.
    expect(source).not.toContain('is not detected any more');
    const changelog = await fs.readFile(
      path.join(__dirname, '..', '..', 'CHANGELOG.md'),
      'utf-8'
    );
    expect(changelog).not.toMatch(/newline no longer match/);
  });
});
