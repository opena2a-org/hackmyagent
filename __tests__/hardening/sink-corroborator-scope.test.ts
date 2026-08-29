/**
 * HMA-01.AC5 — the two cheap items filed beside #475.
 *
 * The corroborator REGEXES ARE NOT WIDENED HERE and nothing below asserts that
 * they are: `vm.runInNewContext`, `globalThis.eval`, `(0,eval)`, a constructor
 * chain, `Reflect.construct`, dynamic `import()`, `child_process` and
 * `module._compile` still do not corroborate, and closing that belongs to
 * #424's AST dataflow unit. A semantic question answered by a lexical test is
 * the mistake this check has already made twice.
 *
 * What moved is the TEXT the unchanged regexes are asked about:
 *
 *   1. Comments and string literals are not code. `src/hardening/scanner.ts`
 *      self-flagged CRITICAL on the `eval(...)` in one of its own doc comments
 *      and on the `'eval() dynamic execution'` label of a detection rule, and
 *      stayed out of its own score only because `.hmaignore` excludes the path.
 *      The last block below scans the real file with no `.hmaignore` in reach,
 *      so the property is measured on the artifact the issue named rather than
 *      on a fixture that resembles it.
 *   2. The corroborator reads the SAME LINE POPULATION as the presence loop.
 *      Both now skip a line over MAX_LINE_LENGTH, so an `eval(` inside a
 *      minified bundle line cannot corroborate `.codePointAt(` and a range
 *      literal read from ordinary lines.
 *
 * Every suppression block below is paired with a NON-VACUITY twin that must
 * still reach CRITICAL, because the cheapest way to pass a "does not fire"
 * suite is to stop the check firing at all. The minified pair differs only in
 * the length of one padding string.
 *
 * No invisible codepoint is WRITTEN anywhere in this file. The one matcher that
 * needs them builds them from numeric codepoints at run time: a file asserting
 * that another file carries none must not carry one itself, and an editor that
 * renders escape sequences has put ten of them into this repo once already.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

/** Mirrors `MAX_LINE_LENGTH` in `src/hardening/scanner.ts`, which is module-private. */
const MAX_LINE_LENGTH = 10000;

/** The corroborator, character for character as the scanner carries it. */
const SINK_PATTERNS = [
  /(?:^|[^\w.$])eval\s*\(/,
  /(?:^|[^\w.$])(?:new\s+)?Function\s*\(/,
];

/**
 * The decoder shape the finding is actually about: reads codepoints in the
 * variation-selector range. Carries no sink and no invisible payload of its
 * own, so whatever a fixture adds to it is the only thing under test.
 */
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

describe('HMA-01.AC5: the execution-sink corroborator reads code, and reads the same lines', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-sink-scope-'));
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({ name: 'sink-scope-project', version: '1.0.0' })
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

  /**
   * A fixture only measures the sink corroborator while the decoder shape is
   * intact and the raw text still matches the unchanged regexes — otherwise a
   * MEDIUM verdict proves the fixture stopped reaching the check, not that the
   * sink was correctly ignored.
   */
  function expectFixtureStillTriggersTheOldReader(content: string): void {
    expect(content).toContain('.codePointAt(');
    expect(content).toMatch(/0x(?:FE0|E010)/);
    expect(
      SINK_PATTERNS.some((p) => p.test(content)),
      'the fixture no longer matches the sink regexes, so this measures nothing'
    ).toBe(true);
  }

  it('HMA-01.AC5 a doc comment naming eval( does not corroborate the decoder shape', async () => {
    // The `eval(` sits on a CONTINUATION line of a block comment, which is the
    // case a per-line reader cannot see: that line carries no opener of its own.
    const content = [
      '/**',
      ' * Reads variation-selector codepoints for inspection.',
      ' *',
      ' * Never hand the result to eval(payload) — this decodes for a human,',
      ' * not for an executor.',
      ' */',
      ...DECODER_SHAPE,
      'module.exports = { read };',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'doc-comment.js'), content);

    const findings = await stego002For('doc-comment.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(['critical', 'high']).not.toContain(findings[0].severity);
    expect(findings[0].message).toContain('uncorroborated');
  });

  it('HMA-01.AC5 a detection-rule label string holding eval() does not corroborate', async () => {
    // The shape our own scanner carries: a regex literal whose escapes stop the
    // corroborator matching, beside a human-readable label where it does match.
    const content = [
      'const RULES = [',
      "  { pattern: /eval\\s*\\(/, label: 'eval() dynamic execution' },",
      "  { pattern: /new\\s+Function\\s*\\(/, label: 'new Function() dynamic execution' },",
      '];',
      ...DECODER_SHAPE,
      'module.exports = { read, RULES };',
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'rules.js'), content);

    const findings = await stego002For('rules.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(['critical', 'high']).not.toContain(findings[0].severity);
  });

  it('HMA-01.AC5 a real call after a mention on the SAME line still corroborates', async () => {
    // Non-vacuity for the two blocks above, and the reason the line is walked to
    // its end rather than answered from its first match. A reader that stopped at
    // the label would call this file a lead.
    const content = [
      ...DECODER_SHAPE,
      "const label = 'eval() dynamic execution'; eval(read(process.argv[2]).join(''));",
    ].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'mention-then-call.js'), content);

    const findings = await stego002For('mention-then-call.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });

  it('HMA-01.AC5 an eval( on a line over MAX_LINE_LENGTH does not corroborate', async () => {
    // A minified bundle is one very long line. The presence loop has always
    // skipped it; the corroborator used to read it anyway, so the bundle
    // corroborated signals read from the ordinary lines above it.
    const bundle = `const BUNDLE = "${'a'.repeat(MAX_LINE_LENGTH)}";eval(BUNDLE);`;
    expect(bundle.length).toBeGreaterThan(MAX_LINE_LENGTH);
    const content = [...DECODER_SHAPE, bundle].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'minified.js'), content);

    const findings = await stego002For('minified.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(['critical', 'high']).not.toContain(findings[0].severity);
  });

  it('HMA-01.AC5 the same eval( on a line within MAX_LINE_LENGTH still corroborates', async () => {
    // The twin of the block above, differing ONLY in the padding length. Without
    // it, "minified.js is MEDIUM" is equally well explained by the fixture never
    // reaching the check.
    const short = `const BUNDLE = "${'a'.repeat(64)}";eval(BUNDLE);`;
    expect(short.length).toBeLessThanOrEqual(MAX_LINE_LENGTH);
    const content = [...DECODER_SHAPE, short].join('\n');
    expectFixtureStillTriggersTheOldReader(content);
    await fs.writeFile(path.join(tempDir, 'short-line.js'), content);

    const findings = await stego002For('short-line.js');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('execution sink');
  });
});

/**
 * The artifact #475 actually named. Scanned as a copy in a temp directory, so
 * no `.hmaignore` is in reach and the exemption that has been hiding this from
 * our own score is not available.
 */
describe('HMA-01.AC5: the scanner does not self-flag CRITICAL without .hmaignore', () => {
  let scanner: HardeningScanner;
  let tempDir: string;
  const SOURCE = path.join(__dirname, '..', '..', 'src', 'hardening', 'scanner.ts');

  const VARIATION_SELECTOR_FIRST = 0xfe00;
  const VARIATION_SELECTOR_LAST = 0xfe0f;
  const TAG_SUPPLEMENT_FIRST = 0xe0100;
  const TAG_SUPPLEMENT_LAST = 0xe01ef;

  /**
   * The payload classes that DO corroborate this finding, built from codepoints
   * so this file carries none of them. See the header.
   */
  const PAYLOAD_CLASS = new RegExp(
    '['
      + String.fromCodePoint(VARIATION_SELECTOR_FIRST)
      + '-'
      + String.fromCodePoint(VARIATION_SELECTOR_LAST)
      + ']|['
      + String.fromCodePoint(TAG_SUPPLEMENT_FIRST)
      + '-'
      + String.fromCodePoint(TAG_SUPPLEMENT_LAST)
      + ']',
    'u',
  );

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-self-scan-'));
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({ name: 'self-scan-project', version: '1.0.0' })
    );
    await fs.copyFile(SOURCE, path.join(tempDir, 'scanner.ts'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it(
    'HMA-01.AC5 src/hardening/scanner.ts is a MEDIUM lead, not a CRITICAL, on its own text',
    async () => {
      const source = await fs.readFile(SOURCE, 'utf-8');

      // The two presence signals are there, so the finding is reached at all.
      expect(source).toContain('.codePointAt(');
      expect(source).toMatch(/0x(?:FE0|E010)/);
      // The raw text still matches the unchanged corroborator regexes — that is
      // the whole defect: every one of those matches is a comment or a string.
      expect(SINK_PATTERNS.some((p) => p.test(source))).toBe(true);
      // And the OTHER corroborator must be absent, or a CRITICAL here would be
      // correct for a reason this test is not about. The file does carry one
      // U+200B, deliberately, escaping a globstar inside a JSDoc — a zero-width
      // char is not a variation-selector or tag-character payload and has not
      // corroborated this finding since #475's first half.
      expect(PAYLOAD_CLASS.test(source)).toBe(false);
      // Non-vacuity control: a matcher that matched nothing would satisfy the
      // line above for the wrong reason.
      expect(
        PAYLOAD_CLASS.test('a' + String.fromCodePoint(VARIATION_SELECTOR_FIRST) + 'b'),
      ).toBe(true);
      expect(
        PAYLOAD_CLASS.test('a' + String.fromCodePoint(TAG_SUPPLEMENT_FIRST) + 'b'),
      ).toBe(true);

      const result = await scanner.scan({ targetDir: tempDir });
      const stego002 = result.findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'scanner.ts'
      );

      // Still REPORTED. Suppressing it would be the other failure mode: the file
      // does read codepoints in the range, and saying so costs a line of output.
      // What it must not do is fail a pipeline on its own doc comments.
      expect(stego002.length).toBe(1);
      expect(stego002[0].severity).toBe('medium');
      expect(['critical', 'high']).not.toContain(stego002[0].severity);
    },
    180_000
  );
});
