import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { isMatchInsideStringLiteral } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

/**
 * NEMO-009 multi-line template-literal false positive.
 *
 * The TS/JS gate asked `isMatchInsideStringLiteral(line, idx)` about one line
 * at a time, and the predicate lexes its line from column 0 in code state — so
 * a token standing alone on a CONTINUATION line of a multi-line backtick
 * literal (a skill document held in a template, say) was read as real code and
 * flagged CRITICAL. The gate now threads a template-literal state across the
 * line boundary, the `blankCommentRegions(line, state)` shape the AST sink
 * walker already uses, and blanks only the literal's own span: a real eval()
 * outside the literal, in the same file, still fires.
 */
describe('NEMO-009 multi-line template-literal gating', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-nemo009-tpl-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  type Finding = {
    checkId?: string;
    passed?: boolean;
    name?: string;
    severity?: string;
    line?: number;
  };

  function nemo009(findings: Finding[]) {
    return findings.filter((f) => f.checkId === 'NEMO-009' && !f.passed);
  }

  // The AC1 fixture: the backtick opens on line 1 and the eval( token on
  // line 4 is text inside the literal.
  const AC1_LINES = [
    'const SKILL = `',
    '# Demo skill',
    'Run this:',
    'eval(code);',
    '`;',
    'export const skill = SKILL;',
  ];

  it('HMA-65.AC1 eval( alone on a continuation line of a multi-line template literal does not fire', async () => {
    await fs.writeFile(path.join(tempDir, 'skill.ts'), AC1_LINES.join('\n'));
    const result = await scanner.scan({ targetDir: tempDir });
    expect(nemo009(result.findings)).toHaveLength(0);
  });

  it('HMA-65.AC2 a real eval( outside the literal, in the same file, still reports at its own line', async () => {
    const lines = [...AC1_LINES, 'const bad = eval(userInput);'];
    await fs.writeFile(path.join(tempDir, 'skill.ts'), lines.join('\n'));
    const result = await scanner.scan({ targetDir: tempDir });
    const hits = nemo009(result.findings);
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(7);
    expect(hits[0].name).toBe('Unsafe deserialization: eval()');
    expect(hits[0].severity).toBe('critical');
  });

  it('HMA-65.AC3 the closing backtick returns the walk to code state: eval( on the next line reports', async () => {
    const ts = [
      'const t = `',
      'plain text',
      '`;',
      'eval(userInput);',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'closed.ts'), ts);
    const result = await scanner.scan({ targetDir: tempDir });
    const hits = nemo009(result.findings);
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(4);
  });

  it('HMA-65.AC3 a template literal never closed before end of file suppresses tokens after the opener', async () => {
    const ts = [
      'const t = `',
      'some text',
      'eval(code);',
      'new Function("x")();',
      'more text',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'unclosed.ts'), ts);
    const result = await scanner.scan({ targetDir: tempDir });
    expect(nemo009(result.findings)).toHaveLength(0);
  });

  it('HMA-65.AC4 all four TS/JS match sites suppress inside the literal span', async () => {
    const ts = [
      'const DOC = `',
      'eval(a);',
      'globalThis.eval(b);',
      'new Function("x")();',
      'JSON5.parse(raw);',
      '`;',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'doc.ts'), ts);
    const result = await scanner.scan({ targetDir: tempDir });
    expect(nemo009(result.findings)).toHaveLength(0);
  });

  it('HMA-65.AC4 an eval( inside ${...} interpolation of a continuation line is code and still fires', async () => {
    const ts = [
      'const msg = `',
      'value: ${eval(expr)}',
      '`;',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'interp.ts'), ts);
    const result = await scanner.scan({ targetDir: tempDir });
    const hits = nemo009(result.findings);
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(2);
  });

  it('HMA-65.AC4 isMatchInsideStringLiteral keeps its two-argument per-line signature and answers', () => {
    expect(isMatchInsideStringLiteral.length).toBe(2);
    expect(isMatchInsideStringLiteral('eval(userInput);', 0)).toBe(false);
  });

  it('HMA-65.AC4 a backtick inside a multi-line block comment does not open a phantom template', async () => {
    const ts = [
      '/**',
      ' * ```ts',
      ' * example();',
      ' * ```',
      ' */',
      'eval(userInput);',
    ].join('\n');
    await fs.writeFile(path.join(tempDir, 'doc-fence.ts'), ts);
    const result = await scanner.scan({ targetDir: tempDir });
    const hits = nemo009(result.findings);
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(6);
  });

  it('HMA-65.AC5 the CHANGELOG names the false-positive class without internal artifact paths or governance tags', async () => {
    const changelog = await fs.readFile(
      path.join(__dirname, '..', '..', 'CHANGELOG.md'),
      'utf-8',
    );
    // The entry may sit under [Unreleased] or under a version cut above 0.32.0.
    const sections = changelog.split(/^## /m).filter((s) => {
      const heading = s.slice(0, s.indexOf('\n'));
      if (heading.startsWith('[Unreleased]')) return true;
      const v = heading.match(/^\[(\d+)\.(\d+)\.(\d+)\]/);
      if (!v) return false;
      const [maj, min, pat] = [Number(v[1]), Number(v[2]), Number(v[3])];
      return maj > 0 || min > 32 || (min === 32 && pat > 0);
    });
    const entries = sections
      .join('\n')
      .split(/^### /m)
      .filter(
        (e) =>
          /NEMO-009/.test(e) &&
          /template literal/i.test(e) &&
          /multi-?line/i.test(e) &&
          /line boundary/i.test(e),
      );
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(entry).not.toMatch(/HMA-\d/);
      expect(entry).not.toMatch(/qgf\//);
      expect(entry).not.toMatch(/roadmap\//);
    }
  });
});
