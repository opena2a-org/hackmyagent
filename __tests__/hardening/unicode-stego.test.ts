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
      expect(stego002[0].severity).toBe('critical');
      expect(stego002[0].passed).toBe(false);
      expect(stego002[0].file).toBe('decoder.js');
      expect(stego002[0].message).toContain('GlassWorm decoder pattern');
    });

    it('detects .codePointAt() with tag character hex literals', async () => {
      const content = [
        'function decode(s) {',
        '  for (let i = 0; i < s.length; i++) {',
        '    const cp = s.codePointAt(i);',
        '    if (cp >= 0xE0100) { return cp; }',
        '  }',
        '}',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'decoder-tags.ts'), content);

      const findings = await scanForUnicodeStego();
      const stego002 = findings.filter((f) => f.checkId === 'UNICODE-STEGO-002');

      expect(stego002.length).toBeGreaterThanOrEqual(1);
      expect(stego002[0].file).toBe('decoder-tags.ts');
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
