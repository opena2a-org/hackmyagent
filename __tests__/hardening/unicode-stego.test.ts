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

    it('detects zero-width characters (U+200B-U+200D) in source files', async () => {
      const content = Buffer.concat([
        Buffer.from('const name = "admin'),
        Buffer.from([0xE2, 0x80, 0x8B]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'zwsp.js'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'zwsp.js'
      );
      expect(stego001.length).toBe(1);
      expect(stego001[0].message).toContain('zero-width');
    });

    it('detects BOM (U+FEFF) in the middle of a file', async () => {
      const content = Buffer.concat([
        Buffer.from('const x = 1;\n'),
        Buffer.from('const y = "test'),
        Buffer.from([0xEF, 0xBB, 0xBF]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'mid-bom.js'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'mid-bom.js'
      );
      expect(stego001.length).toBe(1);
      expect(stego001[0].message).toContain('zero-width');
    });

    it('does NOT flag BOM at the very start of a file', async () => {
      const content = Buffer.concat([
        Buffer.from([0xEF, 0xBB, 0xBF]),
        Buffer.from('const x = "hello";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'start-bom.js'), content);
      const findings = await scanForUnicodeStego();
      const bomOnly = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'start-bom.js'
      );
      expect(bomOnly.length).toBe(0);
    });

    it('detects bidirectional override characters (U+202E RLO)', async () => {
      const content = Buffer.concat([
        Buffer.from('const filename = "'),
        Buffer.from([0xE2, 0x80, 0xAE]),
        Buffer.from('txt.exe";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bidi-override.js'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bidi-override.js'
      );
      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('critical');
      expect(stego001[0].message).toContain('bidirectional');
    });

    it('detects bidirectional isolate characters (U+2066 LRI)', async () => {
      const content = Buffer.concat([
        Buffer.from('const path = "'),
        Buffer.from([0xE2, 0x81, 0xA6]),
        Buffer.from('/etc/passwd";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'bidi-isolate.ts'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'bidi-isolate.ts'
      );
      expect(stego001.length).toBe(1);
      expect(stego001[0].severity).toBe('critical');
      expect(stego001[0].message).toContain('bidirectional');
    });

    it('reports category as supply-chain', async () => {
      const content = Buffer.concat([
        Buffer.from('const x = "'),
        Buffer.from([0xE2, 0x80, 0x8B]),
        Buffer.from('";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'category-check.js'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'category-check.js'
      );
      expect(stego001.length).toBe(1);
      expect(stego001[0].category).toBe('supply-chain');
    });

    it('scans Python files for invisible codepoints', async () => {
      const content = Buffer.concat([
        Buffer.from('name = "admin'),
        Buffer.from([0xE2, 0x80, 0x8C]),
        Buffer.from('"\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'suspect.py'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'suspect.py'
      );
      expect(stego001.length).toBe(1);
    });

    it('scans Markdown files for invisible codepoints', async () => {
      const content = Buffer.concat([
        Buffer.from('# Instructions\n\nRun: '),
        Buffer.from([0xE2, 0x80, 0xAE]),
        Buffer.from('harmless\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'readme.md'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'readme.md'
      );
      expect(stego001.length).toBe(1);
    });

    it('scans YAML files for invisible codepoints', async () => {
      const content = Buffer.concat([
        Buffer.from('key: value'),
        Buffer.from([0xE2, 0x80, 0x8B]),
        Buffer.from('\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'config.yaml'), content);
      const findings = await scanForUnicodeStego();
      const stego001 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'config.yaml'
      );
      expect(stego001.length).toBe(1);
    });
  });

  describe('UNICODE-STEGO-005: Homoglyph Substitution Detection', () => {
    it('detects Cyrillic a (U+0430) substituted for Latin a', async () => {
      const content = Buffer.concat([
        Buffer.from('const '),
        Buffer.from([0xD0, 0xB0]),
        Buffer.from('dmin = true;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'homoglyph.js'), content);
      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'homoglyph.js'
      );
      expect(stego005.length).toBe(1);
      expect(stego005[0].severity).toBe('high');
      expect(stego005[0].category).toBe('supply-chain');
      expect(stego005[0].message).toContain('homoglyph');
    });

    it('detects Cyrillic o (U+043E) in identifiers', async () => {
      const content = Buffer.concat([
        Buffer.from('const passw'),
        Buffer.from([0xD0, 0xBE]),
        Buffer.from('rd = "secret";\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'cyrillic-o.ts'), content);
      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'cyrillic-o.ts'
      );
      expect(stego005.length).toBe(1);
    });

    it('does not flag homoglyphs in comments', async () => {
      const content = Buffer.concat([
        Buffer.from('// This is '),
        Buffer.from([0xD0, 0xB0]),
        Buffer.from(' comment\nconst x = 1;\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'comment-safe.js'), content);
      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'comment-safe.js'
      );
      expect(stego005.length).toBe(0);
    });

    it('does not scan non-code files for homoglyphs', async () => {
      const content = Buffer.concat([
        Buffer.from('This text has '),
        Buffer.from([0xD0, 0xB0]),
        Buffer.from(' character\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'readme.md'), content);
      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'readme.md'
      );
      expect(stego005.length).toBe(0);
    });

    it('detects homoglyphs in Python files', async () => {
      const content = Buffer.concat([
        Buffer.from('v'),
        Buffer.from([0xD0, 0xB0]),
        Buffer.from('lue = 42\n'),
      ]);
      await fs.writeFile(path.join(tempDir, 'confusable.py'), content);
      const findings = await scanForUnicodeStego();
      const stego005 = findings.filter(
        (f) => f.checkId === 'UNICODE-STEGO-005' && f.file === 'confusable.py'
      );
      expect(stego005.length).toBe(1);
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
        expect(finding.category).toBe('supply-chain');
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
