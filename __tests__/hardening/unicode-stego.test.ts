import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('UNICODE-STEGO checks', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-unicode-stego-'));
    // Create a minimal package.json so the scanner can detect project type
    await fs.writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify({ name: 'test-project', version: '1.0.0' })
    );
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  /**
   * Helper: scan and return only UNICODE-STEGO findings
   */
  async function scanForUnicodeStego(): Promise<SecurityFinding[]> {
    const result = await scanner.scan({ targetDir: tempDir });
    return result.findings.filter((f) => f.checkId.startsWith('UNICODE-STEGO-'));
  }

  describe('UNICODE-STEGO-001: Invisible Codepoint Detection', () => {
    it('detects variation selectors (U+FE00-FE0F) in source files', async () => {
      // Create a .js file with embedded variation selectors
      // U+FE00 = EF B8 80 in UTF-8
      const content = Buffer.concat([
        Buffer.from('const x = "hello'),
        Buffer.from([0xEF, 0xB8, 0x80]), // U+FE00
        Buffer.from([0xEF, 0xB8, 0x8F]), // U+FE0F
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'suspect.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-001');

      expect(stego001.length).toBeGreaterThanOrEqual(1);
      expect(stego001[0].severity).toBe('critical');
      expect(stego001[0].passed).toBe(false);
      expect(stego001[0].file).toBe('suspect.js');
      expect(stego001[0].message).toContain('variation selectors');
    });

    it('detects tag characters (U+E0100-E01EF) in source files', async () => {
      // U+E0100 = F3 A0 84 80 in UTF-8
      const content = Buffer.concat([
        Buffer.from('const y = "world'),
        Buffer.from([0xF3, 0xA0, 0x84, 0x80]), // U+E0100
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'tag-chars.ts'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-001');

      expect(stego001.length).toBeGreaterThanOrEqual(1);
      expect(stego001[0].severity).toBe('critical');
      expect(stego001[0].file).toBe('tag-chars.ts');
      expect(stego001[0].message).toContain('tag characters');
    });

    it('does not flag clean source files', async () => {
      await fs.writeFile(
        path.join(tempDir, 'clean.js'),
        'const x = "hello world";\nconsole.log(x);\n'
      );

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'clean.js'
      );

      expect(stego001.length).toBe(0);
    });

    it('reports only one finding per file even with multiple occurrences', async () => {
      const content = Buffer.concat([
        Buffer.from('const a = "'),
        Buffer.from([0xEF, 0xB8, 0x80]),
        Buffer.from('";\nconst b = "'),
        Buffer.from([0xEF, 0xB8, 0x81]),
        Buffer.from('";\nconst c = "'),
        Buffer.from([0xEF, 0xB8, 0x8F]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'multi.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'multi.js'
      );

      expect(stego001.length).toBe(1);
    });

    it('detects zero-width characters (U+200B-200D) in source files', async () => {
      // U+200B = E2 80 8B (zero-width space)
      const content = Buffer.concat([
        Buffer.from('const x = "hello'),
        Buffer.from([0xE2, 0x80, 0x8B]), // U+200B ZWSP
        Buffer.from('world";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'zwsp.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'zwsp.js'
      );

      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('high'); // zero-width-only is high, not critical
      expect(stego001[0].message).toContain('zero-width');
    });

    it('detects mid-file BOM (U+FEFF) but not start-of-file BOM', async () => {
      // Start-of-file BOM should NOT trigger
      const bomAtStart = Buffer.concat([
        Buffer.from([0xEF, 0xBB, 0xBF]), // BOM at offset 0
        Buffer.from('const x = 1;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bom-start.js'), bomAtStart);

      // Mid-file BOM SHOULD trigger
      const bomMidFile = Buffer.concat([
        Buffer.from('const x = "test'),
        Buffer.from([0xEF, 0xBB, 0xBF]), // BOM mid-file
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bom-mid.js'), bomMidFile);

      const findings = await scanForUnicodeStego();

      const startFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bom-start.js'
      );
      expect(startFindings.length).toBe(0);

      const midFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bom-mid.js'
      );
      expect(midFindings.length).toBe(1);
      expect(midFindings[0].message).toContain('mid-file BOM');
    });

    it('detects bidi override characters (U+202A-202E)', async () => {
      // U+202E = E2 80 AE (right-to-left override)
      const content = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xE2, 0x80, 0xAE]), // U+202E RLO
        Buffer.from('admin";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bidi.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bidi.js'
      );

      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('critical'); // bidi is critical
      expect(stego001[0].message).toContain('bidi overrides');
    });

    it('detects bidi isolate characters (U+2066-2069)', async () => {
      // U+2066 = E2 81 A6 (left-to-right isolate)
      const content = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xE2, 0x81, 0xA6]), // U+2066 LRI
        Buffer.from('test";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bidi-isolate.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bidi-isolate.js'
      );

      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('critical');
    });

    it('zero-width-only files get high severity, not critical', async () => {
      // Only zero-width chars, no bidi/variation/tags
      const content = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xE2, 0x80, 0x8C]), // U+200C ZWNJ
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'zwonly.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'zwonly.js'
      );

      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('high');
    });
  });

  describe('Expanded file type scanning', () => {
    it('detects invisible codepoints in .py files', async () => {
      const content = Buffer.concat([
        Buffer.from('x = "hello'),
        Buffer.from([0xE2, 0x80, 0x8B]), // U+200B
        Buffer.from('"\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'script.py'), content);

      const findings = await scanForUnicodeStego();
      const pyFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'script.py'
      );
      expect(pyFindings.length).toBe(1);
    });

    it('detects invisible codepoints in .md files', async () => {
      const content = Buffer.concat([
        Buffer.from('# Hello '),
        Buffer.from([0xE2, 0x80, 0xAE]), // U+202E bidi
        Buffer.from('World\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'readme.md'), content);

      const findings = await scanForUnicodeStego();
      const mdFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'readme.md'
      );
      expect(mdFindings.length).toBe(1);
    });

    it('detects invisible codepoints in .yaml files', async () => {
      const content = Buffer.concat([
        Buffer.from('key: "value'),
        Buffer.from([0xE2, 0x80, 0x8D]), // U+200D ZWJ
        Buffer.from('"\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'config.yaml'), content);

      const findings = await scanForUnicodeStego();
      const yamlFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'config.yaml'
      );
      expect(yamlFindings.length).toBe(1);
    });
  });

  describe('UNICODE-STEGO-002: GlassWorm Decoder Pattern', () => {
    it('detects .codePointAt() with variation selector hex literals', async () => {
      const content = [
        'function decode(input) {',
        '  const result = [];',
        '  for (let i = 0; i < input.length; i++) {',
        '    const cp = input.codePointAt(i);',
        '    if (cp >= 0xFE00 && cp <= 0xFE0F) {',
        '      result.push(cp - 0xFE00);',
        '    }',
        '  }',
        '  return String.fromCharCode(...result);',
        '}',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'decoder.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-002');

      expect(stego002.length).toBeGreaterThanOrEqual(1);
      // Uncorroborated: this fixture reconstitutes, but nothing here executes the
      // result and the file carries no invisible codepoints. Capability, not malice.
      // The corroborated cases are pinned in the corroboration block below.
      expect(stego002[0].severity).toBe('medium');
      expect(stego002[0].passed).toBe(false);
      expect(stego002[0].file).toBe('decoder.js');
      expect(stego002[0].message).toContain('GlassWorm decoder shape');
    });

    it('detects .codePointAt() with tag character hex literals', async () => {
      const content = [
        'function decode(s) {',
        '  const out = [];',
        '  for (let i = 0; i < s.length; i++) {',
        '    const cp = s.codePointAt(i);',
        '    if (cp >= 0xE0100) { out.push(cp - 0xE0100); }',
        '  }',
        '  return String.fromCodePoint(...out);',
        '}',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'decoder-tags.ts'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-002');

      expect(stego002.length).toBeGreaterThanOrEqual(1);
      expect(stego002[0].file).toBe('decoder-tags.ts');
    });

    // The fixture above used to end `if (cp >= 0xE0100) { return cp; }` with no
    // reconstitution at all, and asserted the check fired on it. That is inspector
    // shaped code, not a decoder, and asserting a finding on it was asserting the
    // false-positive class this check has now been narrowed to exclude. The positive
    // case above keeps the tag-range coverage by reconstituting for real; this
    // negative pins the behaviour that replaced it, so the change is under test in
    // both directions rather than deleted.
    it('does not flag tag-range code that reads codepoints without reconstituting', async () => {
      const content = [
        'function classify(s) {',
        '  for (let i = 0; i < s.length; i++) {',
        '    const cp = s.codePointAt(i);',
        '    if (cp >= 0xE0100) { return cp; }',
        '  }',
        '}',
      ].join('\n');
      // The filename must not carry an exemption keyword. Named `inspector-tags.ts`
      // this test passed against the PRE-FIX scanner as well, because "inspect" hit
      // the old path regex — a negative case that would have proved nothing.
      const fixtureName = 'tag-range-reader.ts';
      expect(fixtureName).not.toMatch(/analyz|detect|scan|check|inspect|enhanc|stego/i);
      await fs.writeFile(path.join(tempDir, fixtureName), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === fixtureName
      );

      expect(stego002.length).toBe(0);
    });

    it('does not flag .codePointAt() without suspicious hex literals', async () => {
      const content = [
        'function getCodePoint(str) {',
        '  return str.codePointAt(0);',
        '}',
        'console.log(getCodePoint("A")); // 65 = 0x41',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'safe-codepoint.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'safe-codepoint.js'
      );

      expect(stego002.length).toBe(0);
    });
  });

  /**
   * UNICODE-STEGO-002 fired on defensive code: a log sanitiser, in three repositories
   * at once, i.e. on the countermeasure to the attack the check is named after.
   * Measured precision on real-world code was 0/7 and the only true positives ever
   * observed were fixtures written for this check.
   *
   * The root cause was that reconstitution — String.fromCodePoint/fromCharCode, the
   * decoder half of GlassWorm — was only one input to an exemption whose other input
   * was a regex over the file PATH. Code that inspects codepoints without rebuilding
   * a string from them therefore fired unless it was lucky enough to be named like an
   * analyzer. Every fixture below is red-proofed against the pre-fix scanner: each
   * negative case fired before this change.
   */
  describe('UNICODE-STEGO-002: reconstitution is required, and severity is corroborated', () => {
    it('does not flag a log sanitiser that names the ranges it defends against', async () => {
      // Excerpt taken verbatim from csnp/cypres scripts/lib/log-safe.mjs, the file
      // that gate-blocked three repositories. The range table and safeLog are the
      // two things the check reads.
      const content = [
        'const HAZARD_RANGES = [',
        '  [0x0000, 0x001f], // Cc: C0 controls, including NUL, ESC, CR and LF',
        '  [0x007f, 0x009f], // Cc: DEL, then C1. U+009B is a one-character CSI',
        '  [0x00ad, 0x00ad], // Cf: SOFT HYPHEN',
        '  [0x180b, 0x180f], // DI: Mongolian free variation selectors, MVS and FVS4',
        '  [0x200b, 0x200f], // Cf: zero width space, non-joiner, joiner, LRM, RLM',
        '  [0xfe00, 0xfe0f], // DI: VARIATION SELECTOR-1 to -16',
        '  [0xfeff, 0xfeff], // Cf: ZERO WIDTH NO-BREAK SPACE, the BOM',
        '  [0xe0100, 0xe01ef], // DI: VARIATION SELECTOR-17 to -256',
        '];',
        '',
        'export const isLogHazard = (cp) => {',
        '  for (const [lo, hi] of HAZARD_RANGES) if (cp >= lo && cp <= hi) return true;',
        '  return false;',
        '};',
        '',
        'export function safeLog(value) {',
        '  let out = "";',
        '  for (const ch of String(value ?? "")) {',
        '    const cp = ch.codePointAt(0);',
        '    out += isLogHazard(cp) ? "<U+" + cp.toString(16).toUpperCase() + ">" : ch;',
        '  }',
        '  return out;',
        '}',
      ].join('\n');

      // Fixture integrity: this fixture is only a regression test while it still
      // carries the two tokens the check reads and lacks the one it now requires.
      // Without these three assertions the fixture could drift into passing for the
      // wrong reason and the regression would go silent.
      expect(content).toContain('0xfe00');
      expect(content).toContain('.codePointAt(');
      expect(content).not.toMatch(/String\.from(?:CodePoint|CharCode)\s*\(/);

      await fs.writeFile(path.join(tempDir, 'log-safe.mjs'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'log-safe.mjs'
      );

      expect(stego002.length).toBe(0);
    });

    it('does not flag a logging library whose two tokens are hundreds of lines apart', async () => {
      // The check sets two file-global booleans with no AST, no scope and no
      // dataflow, so any file containing both tokens anywhere fired. `consola` and
      // `graphemer` are both real-world false positives of exactly this shape;
      // graphemer's two tokens sit roughly 9,000 lines apart.
      const head = ['export function formatWidth(str) {', '  return str.codePointAt(0);', '}'];
      const filler = Array.from({ length: 400 }, (_, i) => `// unrelated line ${i}`);
      const tail = ['const VARIATION_SELECTOR_START = 0xFE00;', 'export { VARIATION_SELECTOR_START };'];
      const content = [...head, ...filler, ...tail].join('\n');
      await fs.writeFile(path.join(tempDir, 'logger.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'logger.js'
      );

      expect(stego002.length).toBe(0);
    });

    it('does not flag a detection analyzer renamed away from an analyzer filename', async () => {
      // Before this change our own stego analyzer was held clean only by the path
      // regex, which this scanner's own comment called an attacker-controllable weak
      // signal. Copied to a neutral filename it self-flagged. The filename is no
      // longer consulted at all, so the bypass is gone rather than relocated.
      const content = [
        'export function findHiddenCodepoints(source: string): number[] {',
        '  const hits: number[] = [];',
        '  for (let i = 0; i < source.length; i++) {',
        '    const cp = source.codePointAt(i)!;',
        '    if (cp >= 0xFE00 && cp <= 0xFE0F) hits.push(cp);',
        '    if (cp >= 0xE0100 && cp <= 0xE01EF) hits.push(cp);',
        '  }',
        '  return hits;',
        '}',
      ].join('\n');
      expect(content).not.toMatch(/analyz|detect|scan|check|inspect|enhanc|stego/i);
      await fs.writeFile(path.join(tempDir, 'util-helper.ts'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'util-helper.ts'
      );

      expect(stego002.length).toBe(0);
    });

    it('KNOWN GAP: the decimal spelling of a working decoder is not detected', async () => {
      // Tracked, not fixed here. The hex pattern is a spelling test, so a decoder
      // that writes 917760 instead of 0xE0100 evades it while doing strictly more
      // than any fixture that fires: it reconstitutes AND executes. The signature
      // therefore selects for honest spelling, which correlates with defensive code.
      // Closing it belongs with the AST work, not with a wider regex, because a
      // wider regex reopens the false-positive class this change closed.
      // Upstream: hackmyagent#467.
      const content = [
        'function decode(input) {',
        '  const out = [];',
        '  for (let i = 0; i < input.length; i++) {',
        '    const cp = input.codePointAt(i);',
        '    if (cp >= 917760 && cp <= 917999) { out.push(cp - 917760); }',
        '  }',
        '  return String.fromCodePoint(...out);',
        '}',
        'eval(decode(process.argv[2]));',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'decimal-decoder.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'decimal-decoder.js'
      );

      // Asserted as ZERO deliberately. If a future change makes this fire, this test
      // fails and the gap closes with a person reading it, rather than the marker
      // rotting into a comment nobody re-runs.
      expect(stego002.length).toBe(0);
    });

    it('escalates to critical when the decoded string can reach an execution sink', async () => {
      const content = [
        'function decode(input) {',
        '  const result = [];',
        '  for (let i = 0; i < input.length; i++) {',
        '    const cp = input.codePointAt(i);',
        '    if (cp >= 0xFE00 && cp <= 0xFE0F) { result.push(cp - 0xFE00); }',
        '  }',
        '  return String.fromCharCode(...result);',
        '}',
        'eval(decode(process.argv[2]));',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'live-decoder.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'live-decoder.js'
      );

      expect(stego002.length).toBe(1);
      expect(stego002[0].severity).toBe('critical');
      expect(stego002[0].message).toContain('execution sink');
    });

    it('escalates to critical when the invisible payload is present in the same file', async () => {
      // U+FE00 written into the file as raw bytes, so UNICODE-STEGO-001 fires here
      // too: the decoder and the payload it would decode are in the same place.
      const content = Buffer.concat([
        Buffer.from(
          [
            'function decode(input) {',
            '  const result = [];',
            '  for (let i = 0; i < input.length; i++) {',
            '    const cp = input.codePointAt(i);',
            '    if (cp >= 0xFE00 && cp <= 0xFE0F) { result.push(cp - 0xFE00); }',
            '  }',
            '  return String.fromCharCode(...result);',
            '}',
            'const payload = "seed',
          ].join('\n')
        ),
        Buffer.from([0xEF, 0xB8, 0x80]), // U+FE00 VARIATION SELECTOR-1
        Buffer.from('";\nmodule.exports = decode(payload);\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'payload-carrier.js'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'payload-carrier.js'
      );
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'payload-carrier.js'
      );

      expect(stego001.length).toBe(1);
      expect(stego002.length).toBe(1);
      expect(stego002[0].severity).toBe('critical');
      expect(stego002[0].message).toContain('invisible codepoints');
    });

    it('reports the earlier of the two signals, not the first .codePointAt', async () => {
      // The range literal that discriminates the finding usually sits in a table
      // above the loop that reads it. Reporting the first .codePointAt sent readers
      // past the line that actually caused the finding.
      const content = [
        'const VS_LOW = 0xFE00;', // line 1: the discriminating literal
        'const VS_HIGH = 0xFE0F;',
        'function decode(input) {',
        '  const out = [];',
        '  for (const ch of input) {',
        '    const cp = ch.codePointAt(0);', // line 6: the first codePointAt
        '    if (cp >= VS_LOW && cp <= VS_HIGH) out.push(cp - VS_LOW);',
        '  }',
        '  return String.fromCodePoint(...out);',
        '}',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'table-first.js'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-002' && f.file === 'table-first.js'
      );

      expect(stego002.length).toBe(1);
      expect(stego002[0].line).toBe(1);
      expect(stego002[0].message).toContain('range literal at line 1');
      expect(stego002[0].message).toContain('.codePointAt at line 6');
    });
  });

  describe('UNICODE-STEGO-003: Eval on Empty String', () => {
    it('detects eval() with invisible payload (few visible chars, many bytes)', async () => {
      // Build eval('') where the string has >100 invisible bytes but <5 visible chars
      const invisiblePayload: number[] = [];
      for (let i = 0; i < 40; i++) {
        // U+FE00 = EF B8 80 (3 bytes each, 40 * 3 = 120 bytes)
        invisiblePayload.push(0xEF, 0xB8, 0x80);
      }
      const content = Buffer.concat([
        Buffer.from("eval('"),
        Buffer.from(invisiblePayload),
        Buffer.from("');\n"),
      ]);
      await fs.writeFile(path.join(tempDir, 'eval-hidden.js'), content);

      const findings = await scanForUnicodeStego();
      const stego003 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-003');

      expect(stego003.length).toBeGreaterThanOrEqual(1);
      expect(stego003[0].severity).toBe('critical');
      expect(stego003[0].passed).toBe(false);
      expect(stego003[0].file).toBe('eval-hidden.js');
      expect(stego003[0].message).toMatch(/visible chars/);
    });

    it('detects Function() with invisible payload', async () => {
      const invisiblePayload: number[] = [];
      for (let i = 0; i < 40; i++) {
        invisiblePayload.push(0xEF, 0xB8, 0x80);
      }
      const content = Buffer.concat([
        Buffer.from("new Function('"),
        Buffer.from(invisiblePayload),
        Buffer.from("');\n"),
      ]);
      await fs.writeFile(path.join(tempDir, 'func-hidden.js'), content);

      const findings = await scanForUnicodeStego();
      const stego003 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-003' && f.file === 'func-hidden.js'
      );

      expect(stego003.length).toBeGreaterThanOrEqual(1);
    });

    it('does not flag eval() with normal string content', async () => {
      const content = "eval('console.log(\"hello world\")');\n";
      await fs.writeFile(path.join(tempDir, 'safe-eval.js'), content);

      const findings = await scanForUnicodeStego();
      const stego003 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-003' && f.file === 'safe-eval.js'
      );

      expect(stego003.length).toBe(0);
    });
  });

  describe('UNICODE-STEGO-004: Tag Character Block Presence', () => {
    it('detects tag block characters (U+E0000-U+E00FF) not caught by 001', async () => {
      // U+E0001 = F3 A0 80 81 (in the tag block but NOT in U+E0100+ range)
      const content = Buffer.concat([
        Buffer.from('const z = "test'),
        Buffer.from([0xF3, 0xA0, 0x80, 0x81]), // U+E0001
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'tag-block.js'), content);

      const findings = await scanForUnicodeStego();
      const stego004 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-004' && f.file === 'tag-block.js'
      );

      expect(stego004.length).toBe(1);
      expect(stego004[0].severity).toBe('high');
      expect(stego004[0].passed).toBe(false);
    });

    it('does not duplicate when 001 already flagged tag characters', async () => {
      // U+E0100 = F3 A0 84 80 (triggers 001, should NOT also trigger 004)
      const content = Buffer.concat([
        Buffer.from('const y = "test'),
        Buffer.from([0xF3, 0xA0, 0x84, 0x80]), // U+E0100
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'tag-both.ts'), content);

      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'tag-both.ts'
      );
      const stego004 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-004' && f.file === 'tag-both.ts'
      );

      expect(stego001.length).toBe(1);
      expect(stego004.length).toBe(0);
    });

    it('does not flag files without tag block characters', async () => {
      await fs.writeFile(
        path.join(tempDir, 'normal.tsx'),
        'export default function App() { return <div>Hello</div>; }\n'
      );

      const findings = await scanForUnicodeStego();
      const stego004 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-004' && f.file === 'normal.tsx'
      );

      expect(stego004.length).toBe(0);
    });
  });

  describe('findSourceFiles behavior', () => {
    it('skips node_modules directory', async () => {
      await fs.mkdir(path.join(tempDir, 'node_modules', 'pkg'), { recursive: true });
      const nmContent = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xEF, 0xB8, 0x80]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'node_modules', 'pkg', 'index.js'), nmContent);

      const findings = await scanForUnicodeStego();
      const nmFindings = findings.filter(
        (f) => f.file && f.file.includes('node_modules')
      );

      expect(nmFindings.length).toBe(0);
    });

    it('skips hidden directories', async () => {
      await fs.mkdir(path.join(tempDir, '.hidden'), { recursive: true });
      const hiddenContent = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xEF, 0xB8, 0x80]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, '.hidden', 'secret.js'), hiddenContent);

      const findings = await scanForUnicodeStego();
      const hiddenFindings = findings.filter(
        (f) => f.file && f.file.includes('.hidden')
      );

      expect(hiddenFindings.length).toBe(0);
    });

    it('scans nested subdirectories', async () => {
      await fs.mkdir(path.join(tempDir, 'src', 'utils'), { recursive: true });
      const nestedContent = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xEF, 0xB8, 0x80]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'src', 'utils', 'helper.ts'), nestedContent);

      const findings = await scanForUnicodeStego();
      const nestedFindings = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === path.join('src', 'utils', 'helper.ts')
      );

      expect(nestedFindings.length).toBe(1);
    });
  });

  describe('UNICODE-STEGO-005: Homoglyph Confusable Detection', () => {
    it('detects Cyrillic homoglyphs in non-comment code', async () => {
      // U+0410 = Cyrillic A (D0 90 in UTF-8), looks identical to Latin A
      const content = Buffer.concat([
        Buffer.from('const '),
        Buffer.from([0xD0, 0x90]), // Cyrillic A
        Buffer.from('dmin = true;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'homoglyph.js'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'homoglyph.js'
      );

      expect(stego005.length).toBe(1);
      expect(stego005[0].severity).toBe('high');
      expect(stego005[0].passed).toBe(false);
      expect(stego005[0].message).toContain('U+0410');
    });

    it('detects Cyrillic lowercase homoglyphs', async () => {
      // U+0435 = Cyrillic e (D0 B5 in UTF-8)
      const content = Buffer.concat([
        Buffer.from('const t'),
        Buffer.from([0xD0, 0xB5]), // Cyrillic e
        Buffer.from('st = 1;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'homo-lower.js'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'homo-lower.js'
      );

      expect(stego005.length).toBe(1);
    });

    it('skips homoglyphs in comment lines (// prefix)', async () => {
      const content = Buffer.concat([
        Buffer.from('// '),
        Buffer.from([0xD0, 0x90]), // Cyrillic A in a comment
        Buffer.from('dmin note\n'),
        Buffer.from('const x = 1;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'comment-slash.js'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'comment-slash.js'
      );

      expect(stego005.length).toBe(0);
    });

    it('skips homoglyphs in comment lines (# prefix)', async () => {
      const content = Buffer.concat([
        Buffer.from('# '),
        Buffer.from([0xD0, 0x90]), // Cyrillic A in a Python comment
        Buffer.from('dmin note\n'),
        Buffer.from('x = 1\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'comment-hash.py'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'comment-hash.py'
      );

      expect(stego005.length).toBe(0);
    });

    it('skips homoglyphs in block comment lines (* prefix)', async () => {
      const content = Buffer.concat([
        Buffer.from(' * '),
        Buffer.from([0xD0, 0x90]), // Cyrillic A in a block comment line
        Buffer.from('dmin note\n'),
        Buffer.from('const x = 1;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'comment-star.js'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'comment-star.js'
      );

      expect(stego005.length).toBe(0);
    });

    it('reports only one finding per file', async () => {
      const content = Buffer.concat([
        Buffer.from('const '),
        Buffer.from([0xD0, 0x90]), // Cyrillic A
        Buffer.from(' = 1;\nconst '),
        Buffer.from([0xD0, 0x92]), // Cyrillic B
        Buffer.from(' = 2;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'multi-homo.js'), content);

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'multi-homo.js'
      );

      expect(stego005.length).toBe(1);
    });

    it('does not flag files with only ASCII characters', async () => {
      await fs.writeFile(
        path.join(tempDir, 'ascii-only.js'),
        'const admin = true;\nconsole.log(admin);\n'
      );

      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'ascii-only.js'
      );

      expect(stego005.length).toBe(0);
    });
  });

  describe('finding properties', () => {
    it('all findings have required properties with correct values', async () => {
      // Create a file that triggers UNICODE-STEGO-001
      const content = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xEF, 0xB8, 0x80]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'check-props.js'), content);

      const findings = await scanForUnicodeStego();
      const stegoFindings = findings.filter((f) => f.file === 'check-props.js');

      expect(stegoFindings.length).toBeGreaterThanOrEqual(1);
      for (const finding of stegoFindings) {
        expect(finding.checkId).toMatch(/^UNICODE-STEGO-\d{3}$/);
        expect(finding.name).toBeTruthy();
        expect(finding.description).toBeTruthy();
        expect(finding.category).toBe('unicode-stego');
        expect(['critical', 'high']).toContain(finding.severity);
        expect(finding.passed).toBe(false);
        expect(finding.message).toBeTruthy();
        expect(finding.file).toBeTruthy();
        expect(typeof finding.line).toBe('number');
        expect(finding.fixable).toBe(false);
        expect(finding.fix).toBeTruthy();
      }
    });
  });
});
