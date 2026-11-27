import { describe, it, expect } from 'vitest';
import { buildCodeView, isConstStringLiteralBinding } from '../../src/hardening/toctou-const-binding';

const src = (...lines: string[]): string => lines.join('\n');

describe('isConstStringLiteralBinding (TOCTOU-001 constant-path suppression)', () => {
  it('accepts a module const bound to a string literal and only read afterwards', () => {
    const code = src(
      "const TOOL='/usr/bin/true'",
      'export function run() {',
      '  if (existsSync(TOOL)) spawn(TOOL, []);',
      '}',
    );
    expect(isConstStringLiteralBinding(code, 'TOOL')).toBe(true);
  });

  it('accepts export, a string annotation, as const, double quotes and plain templates', () => {
    for (const decl of [
      'export const TOOL = "/usr/bin/true";',
      "const TOOL: string = '/usr/bin/true';",
      "const TOOL = '/usr/bin/true' as const;",
      'const TOOL = `/usr/bin/true`;',
    ]) {
      const code = src(decl, 'if (existsSync(TOOL)) { spawn(TOOL, []); }');
      expect(isConstStringLiteralBinding(code, 'TOOL'), decl).toBe(true);
    }
  });

  it('rejects a non-literal initializer', () => {
    for (const decl of [
      'const TOOL = process.env.TOOL;',
      "const TOOL = '/usr/bin/' + name;",
      'const TOOL = `/usr/bin/${name}`;',
      "const TOOL = '/usr/bin/true'\n+ suffix;",
      "let TOOL = '/usr/bin/true';",
      "var TOOL = '/usr/bin/true';",
    ]) {
      const code = src(decl, 'if (existsSync(TOOL)) spawn(TOOL, []);');
      expect(isConstStringLiteralBinding(code, 'TOOL'), decl).toBe(false);
    }
  });

  it('does not read a declaration inside a comment or a string', () => {
    for (const fake of [
      "// const p = '';",
      "/* const p = '/usr/bin/true'; */",
      "/*\nconst p = '/usr/bin/true';\n*/",
      "const doc = \"const p = '/usr/bin/true';\";",
      "const doc = `\nconst p = '/usr/bin/true';\n`;",
    ]) {
      const code = src(fake, 'export function run(p) {', '  if (existsSync(p)) spawn(p, []);', '}');
      expect(isConstStringLiteralBinding(code, 'p'), fake).toBe(false);
    }
  });

  it('rejects a const declared in an inner scope', () => {
    const code = src(
      'function a() {',
      "  const p = '/usr/bin/true';",
      '}',
      'function b() {',
      '  if (existsSync(p)) spawn(p, []);',
      '}',
    );
    expect(isConstStringLiteralBinding(code, 'p')).toBe(false);
  });

  it('rejects a module const shadowed by any other binding of the same name', () => {
    for (const shadow of [
      'function run(p) { if (existsSync(p)) spawn(p, []); }',
      'function run(a, p) { if (existsSync(p)) spawn(p, []); }',
      'const run = (p) => { if (existsSync(p)) spawn(p, []); };',
      'const run = p => { if (existsSync(p)) spawn(p, []); };',
      'function run({ p }) { if (existsSync(p)) spawn(p, []); }',
      'function run() { let p = read(); if (existsSync(p)) spawn(p, []); }',
      'function run() { const [p] = read(); if (existsSync(p)) spawn(p, []); }',
      'try { x(); } catch (p) { if (existsSync(p)) spawn(p, []); }',
      'class A { run(p) { if (existsSync(p)) spawn(p, []); } }',
      'for (const p of list) { if (existsSync(p)) spawn(p, []); }',
    ]) {
      const code = src("const p = '/usr/bin/true';", shadow);
      expect(isConstStringLiteralBinding(code, 'p'), shadow).toBe(false);
    }
  });

  it('rejects a second module-level declaration and imports of the name', () => {
    expect(isConstStringLiteralBinding(
      src("const p = '/a';", "const p = '/b';", 'spawn(p, []);'), 'p',
    )).toBe(false);
    expect(isConstStringLiteralBinding(
      src("import { p } from './x';", "const p = '/a';", 'spawn(p, []);'), 'p',
    )).toBe(false);
  });

  it('ignores property access with the same name', () => {
    const code = src(
      "const TOOL = '/usr/bin/true';",
      'const x = cfg.TOOL;',
      'if (existsSync(TOOL)) spawn(TOOL, []);',
    );
    expect(isConstStringLiteralBinding(code, 'TOOL')).toBe(true);
  });

  it('fails closed when the lexer meets a slash it cannot read', () => {
    // A TypeScript non-null assertion before `/` would otherwise open a
    // phantom regex that hides the shadowing `let p` on the same line.
    const code = src(
      "const p = '/usr/bin/true';",
      'function run(q) { const r = q! / 2; let p = q; /x/; if (existsSync(p)) spawn(p, []); }',
    );
    expect(buildCodeView(code)).toBeNull();
    expect(isConstStringLiteralBinding(code, 'p')).toBe(false);
  });

  it('lexes regex literals and division without blanking code', () => {
    const view = buildCodeView(src(
      'const re = /[/]\\/x/g;',
      'const half = total / 2 / 1;',
      'if (ok) /re/.test(s);',
    ));
    expect(view).not.toBeNull();
    expect(view!.code).toContain('const half = total / 2 / 1;');
  });
});
