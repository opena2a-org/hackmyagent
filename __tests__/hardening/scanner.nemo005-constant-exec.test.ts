import { describe, it, expect, beforeEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { MAX_SOURCE_LENGTH, constantIdentifiers, onlyConstantExecCalls } from '../../src/hardening/constant-exec';
import * as fs from 'fs/promises';
import * as path from 'path';
import { tempDir } from '../helpers/temp-dir';

// NEMO-005 reported execSync calls whose interpolations were all constants
// (process.execPath, a path next to the file, a mkdtemp directory, literals)
// as critical user-controlled command injection. Nothing a user supplies
// reaches such a command. A test file's exec with a real non-constant value
// is still reported, at a lower severity and named as a test.
describe('NEMO-005 constant interpolation', () => {
  let scanner: HardeningScanner;
  let dir: string;

  beforeEach(() => {
    scanner = new HardeningScanner();
    dir = tempDir('hma-nemo005-const-');
  });

  async function nemo005(fileName: string, source: string) {
    const file = path.join(dir, fileName);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, source);
    const result = await scanner.scan({ targetDir: dir });
    return result.allFindings!.filter((f) => f.checkId === 'NEMO-005');
  }

  const gate = [
    "import { execSync } from 'node:child_process';",
    "import { mkdtempSync } from 'node:fs';",
    "import { tmpdir } from 'node:os';",
    "import { join } from 'node:path';",
    "const dir = mkdtempSync(join(tmpdir(), 'x-'));",
    "execSync(`${process.execPath} ${join(import.meta.dirname, 'cli.mjs')} --dir ${dir} --flag`);",
  ].join('\n');

  it('a test file execSync built from execPath, a file-relative path, a mkdtemp dir and literals is not reported', async () => {
    expect(await nemo005('test/gate.test.mjs', gate)).toHaveLength(0);
  });

  it('the same constant command in shipped code is not reported as a failure', async () => {
    const found = await nemo005('src/gate.mjs', gate);
    expect(found.filter((f) => !f.passed)).toHaveLength(0);
    expect(found.filter((f) => f.passed)).toHaveLength(1);
  });

  it('CommonJS __dirname, path.resolve and a concatenated literal are constant', async () => {
    const js = [
      "const path = require('path');",
      "const { execSync } = require('child_process');",
      "const cli = path.resolve(__dirname, '..', 'bin', 'cli.js');",
      "const fixtureName = 'fixture-' + 'one';",
      'execSync(`node ${cli} --name ${fixtureName}`);',
    ].join('\n');
    expect((await nemo005('lib/run.js', js)).filter((f) => !f.passed)).toHaveLength(0);
  });

  it('user input in shipped code is still critical', async () => {
    const js = [
      "import { execSync } from 'node:child_process';",
      "const dir = '/tmp';",
      'export function checkout(name) {',
      '  execSync(`git -C ${dir} checkout ${name}`);',
      '}',
    ].join('\n');
    const failed = (await nemo005('src/git.mjs', js)).filter((f) => !f.passed);
    expect(failed).toHaveLength(1);
    expect(failed[0].severity).toBe('critical');
    expect(failed[0].line).toBe(4);
  });

  it('a non-constant interpolation in a test file is reported at low severity, named as a test', async () => {
    const js = [
      "import { execSync } from 'node:child_process';",
      'const input = process.argv[2];',
      'execSync(`echo ${input}`);',
    ].join('\n');
    const failed = (await nemo005('src/echo.test.mjs', js)).filter((f) => !f.passed);
    expect(failed).toHaveLength(1);
    expect(failed[0].severity).toBe('low');
    expect(failed[0].message).toMatch(/test file/);
    expect(failed[0].file).toBe(path.join('src', 'echo.test.mjs'));
  });

  describe('constantIdentifiers', () => {
    it('drops a const that is shadowed by a parameter', () => {
      const ts = ["const name = 'fixed';", 'function run(name) { return name; }'].join('\n');
      expect(constantIdentifiers(ts).has('name')).toBe(false);
    });

    it('drops a const declared twice', () => {
      const ts = ["const name = 'fixed';", 'if (x) {', '  const name = req.body.name;', '}'].join('\n');
      expect(constantIdentifiers(ts).has('name')).toBe(false);
    });

    it('drops a const whose value is not constant', () => {
      expect(constantIdentifiers('const id = process.argv[2];').has('id')).toBe(false);
      expect(constantIdentifiers('const id = join(tmpdir(), process.env.ID);').has('id')).toBe(false);
    });

    it('does not read a flag inside a command string as a rebinding', () => {
      const ts = ["const dir = mkdtempSync('x-');", 'execSync(`run --dir ${dir}`);'].join('\n');
      expect(constantIdentifiers(ts).has('dir')).toBe(true);
    });

    it('follows a const built from another const', () => {
      const ts = ["const root = fileURLToPath(new URL('.', import.meta.url));", "const base = join(__dirname, 'x');", "const cli = join(base, 'cli.js');"].join('\n');
      const constants = constantIdentifiers(ts);
      expect(constants.has('cli')).toBe(true);
      expect(constants.has('root')).toBe(false);
    });
  });

  describe('onlyConstantExecCalls', () => {
    it('rejects a call whose command is not a template literal', () => {
      expect(onlyConstantExecCalls('execSync(cmd, { input: `${name}` });', new Set(['cmd']))).toBe(false);
    });

    it('rejects a call that does not close on the line', () => {
      expect(onlyConstantExecCalls('execSync(`${process.execPath} ${name}`,', new Set())).toBe(false);
    });

    it('rejects a line with one constant and one user-controlled call', () => {
      const line = 'execSync(`${process.execPath}`); exec(`rm ${id}`);';
      expect(onlyConstantExecCalls(line, new Set())).toBe(false);
    });

    it('rejects a member of a constant and an unknown call', () => {
      expect(onlyConstantExecCalls('execSync(`ls ${opts.name}`);', new Set(['opts']))).toBe(false);
      expect(onlyConstantExecCalls('execSync(`ls ${getName()}`);', new Set())).toBe(false);
    });
  });

  // The exception applies only when the interpolated name has exactly one
  // binding in the file, a top-level literal `const`, and no other binding of
  // any kind anywhere in it; when the file cannot be read for bindings, the
  // call is reported.
  describe('a name with another binding in the file', () => {
    const header = ["import { execSync } from 'node:child_process';", "const name = 'main';"];

    async function shippedFinding(lines: string[]) {
      const failed = (await nemo005('src/git.ts', lines.join('\n'))).filter((f) => !f.passed);
      expect(failed).toHaveLength(1);
      expect(failed[0].severity).toBe('critical');
      expect(failed[0].line).toBe(lines.findIndex((l) => l.includes('execSync(`')) + 1);
    }

    it('a parameter beside a callback-typed parameter is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout(name: string, done: () => void) { execSync(`git checkout ${name}`); done(); }',
      ]);
    });

    it('a parameter beside a default that calls a function is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout(name: string, opts = defaults()) {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('a destructured parameter is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout({ name }: Options, done: () => void) {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('a rest parameter is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout(done: () => void, ...name: string[]) {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('an arrow function parameter without parentheses is a binding, after a regular expression on its line', async () => {
      await shippedFinding([...header, "export const checkout = withArgs(/'/g, name => execSync(`git checkout ${name}`));"]);
    });

    it('a catch clause parameter is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout() {',
        '  try {',
        '    run();',
        '  } catch ({ name, cause = describeCause() }) {',
        '    execSync(`git checkout ${name}`);',
        '  }',
        '}',
      ]);
    });

    it('a for...of variable is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkoutAll(branches: Map<string, string>) {',
        '  for (const [name] of branches) execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('an inner const in a block is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout(input: string) {',
        '  if (input) {',
        '    const { name }: Options = JSON.parse(input);',
        '    execSync(`git checkout ${name}`);',
        '  }',
        '}',
      ]);
    });

    it('an assignment in another function is a binding', async () => {
      await shippedFinding([
        "import { execSync } from 'node:child_process';",
        "const name: string = 'main';",
        'export function rename(next: string) { name = next; }',
        'export function checkout() {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('a named import is a binding', async () => {
      await shippedFinding([
        "import { execSync } from 'node:child_process';",
        'import {',
        '  name,',
        "} from './config';",
        "const name = 'main';",
        'export function checkout() {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('a multi-line parameter list with generics and a default object literal is a binding', async () => {
      await shippedFinding([
        ...header,
        'export function checkout<T extends Record<string, unknown>>(',
        '  repo: T,',
        '  name: string,',
        '  options: { retries: number; onError: (error: Error) => void } = { retries: 1, onError: (error) => log(error) },',
        '): void {',
        '  execSync(`git checkout ${name}`);',
        '}',
      ]);
    });

    it('a test-only call whose argument is a single top-level literal constant, never rebound, is still not reported', async () => {
      const ts = [
        "import { execSync } from 'node:child_process';",
        "const branchName = 'main';",
        'const port = 8080;',
        'const flagName = `--verbose`;',
        "const special = /[.*+?^${}()|[\\]\\\\]/g;",
        "describe('checkout', () => {",
        "  it('switches branch', () => {",
        '    if (!/^-/.test(branchName) && branchName.replace(special, "").length > 0) {',
        '      execSync(`git checkout ${branchName}`);',
        '      execSync(`serve --port ${port} ${flagName}`);',
        '    }',
        '  });',
        '});',
      ].join('\n');
      expect(await nemo005('test/checkout.test.ts', ts)).toHaveLength(0);
    });

    it('a file whose brackets do not balance is reported', async () => {
      const failed = (
        await nemo005('src/git.ts', [...header, 'export function checkout() {', '  execSync(`git checkout ${name}`);', '}', '}'].join('\n'))
      ).filter((f) => !f.passed);
      expect(failed).toHaveLength(1);
      expect(failed[0].severity).toBe('critical');
    });

    it('a file with a string that does not end, or longer than the length read, has no constants', () => {
      const ts = [...header, 'execSync(`git checkout ${name}`);'];
      expect(constantIdentifiers(ts.join('\n')).has('name')).toBe(true);
      expect(constantIdentifiers([...ts, "const open = 'x;"].join('\n')).has('name')).toBe(false);
      expect(constantIdentifiers([...ts, `// ${'x'.repeat(MAX_SOURCE_LENGTH)}`].join('\n')).has('name')).toBe(false);
    });

    it('a file that calls eval or uses with has no constants', () => {
      expect(constantIdentifiers([...header, 'function f() { eval(code); }'].join('\n')).has('name')).toBe(false);
      expect(constantIdentifiers([...header, 'function f() { with (scope) { run(); } }'].join('\n')).has('name')).toBe(false);
    });

    it('a value that the next line continues is not a constant', () => {
      expect(constantIdentifiers(["const name = 'main'", '  + process.argv[2];'].join('\n')).has('name')).toBe(false);
      expect(constantIdentifiers(["const name = 'main'", 'run();'].join('\n')).has('name')).toBe(true);
    });

    // Parameter lists of random shape, with the name in a binding position:
    // never skipped. The same list with another name there is skipped, so the
    // lists are read, not given up on.
    describe('property: a parameter list of any shape binds the name', () => {
      function mulberry32(seed: number): () => number {
        let a = seed >>> 0;
        return () => {
          a = (a + 0x6d2b79f5) >>> 0;
          let t = a;
          t = Math.imul(t ^ (t >>> 15), t | 1);
          t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
          return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
      }

      function generate(seed: number, bound: string): { source: string; line: string } {
        const rnd = mulberry32(seed);
        const pick = <T>(items: T[]): T => items[Math.floor(rnd() * items.length)];
        const type = (depth: number): string => {
          if (depth <= 0) return pick(['string', 'number', 'boolean', 'unknown']);
          const t = () => type(depth - 1);
          return pick([
            () => `Array<${t()}>`,
            () => `Record<string, ${t()}>`,
            () => `(a: ${t()}, b?: ${t()}) => ${t()}`,
            () => `{ k: ${t()}; f(x: ${t()}): void }`,
            () => `[${t()}, ${t()}]`,
            () => `${t()} | undefined`,
            () => `Promise<(${t()})>`,
          ])();
        };
        const expr = (depth: number): string => {
          if (depth <= 0) return pick(['1', "'('", '")"', '`t`', 'null', '[]', '{}']);
          const e = () => expr(depth - 1);
          return pick([
            () => `f(${e()}, ${e()})`,
            () => `[${e()}, { a: ${e()} }]`,
            () => `(x: ${type(depth - 1)}) => ${e()}`,
            () => `{ a: (${e()}), b: [${e()}] }`,
            () => `/* ) ( */ ${e()}`,
            () => `\`t\${${e()}}\``,
            () => `new Map([[1, ${e()}]])`,
            () => `async () => { return ${e()}; }`,
            () => `(${e()})`,
          ])();
        };
        const depth = () => 1 + Math.floor(rnd() * 3);
        const other = (k: number): string =>
          pick([
            () => `p${k}`,
            () => `p${k}: ${type(depth())}`,
            () => `p${k} = ${expr(depth())}`,
            () => `p${k}: ${type(depth())} = ${expr(depth())}`,
            () => `{ p${k}, q${k}: [r${k}] }: ${type(depth())}`,
            () => `[p${k}, { q${k} = ${expr(depth())} }]`,
          ])();
        const binding = pick([
          () => bound,
          () => `${bound}: ${type(depth())}`,
          () => `${bound} = ${expr(depth())}`,
          () => `${bound}?: ${type(depth())}`,
          () => `{ ${bound} }: ${type(depth())}`,
          () => `{ key: ${bound} }`,
          () => `{ ${bound} = ${expr(depth())} }`,
          () => `[x, ${bound}]`,
          () => `{ k: { j: [${bound}] } } = ${expr(depth())}`,
        ])();
        const rest = rnd() < 0.2 ? `...${bound}: ${type(depth())}[]` : undefined;
        const params = Array.from({ length: Math.floor(rnd() * 4) }, (_, k) => other(k));
        if (rest === undefined) params.splice(Math.floor(rnd() * (params.length + 1)), 0, binding);
        else params.push(rest);
        const separator = pick([', ', ',\n    ']);
        const list = params.join(separator) + (rest === undefined && rnd() < 0.3 ? ',' : '');
        const call = 'execSync(`git checkout ${name}`);';
        const forms = [
          () => [`export function run<T extends Map<string, (x: T) => void>>(${list}): void {`, `  ${call}`, '}'],
          () => [`export const run = (${list}) => {`, `  ${call}`, '};'],
          () => [`export const run = async <T,>(${list}): Promise<void> => {`, `  ${call}`, '};'],
          () => ['class Runner {', `  run(${list}) {`, `    ${call}`, '  }', '}'],
          () => [`export const run = function (${list}) {`, `  ${call}`, '};'],
          () => ['const handlers = {', `  async run(${list}) {`, `    ${call}`, '  },', '};'],
        ];
        if (rest === undefined && !binding.includes('=') && !binding.includes('?')) {
          forms.push(() => ['try {', '  work();', `} catch (${binding}) {`, `  ${call}`, '}']);
          if (binding === bound && params.length === 1) forms.push(() => [`export const run = ${bound} => {`, `  ${call}`, '};']);
        }
        const source = [...header, ...pick(forms)()].join('\n');
        return { source, line: source.split('\n').find((l) => l.includes('execSync(`'))! };
      }

      it('never skips the call when the name is bound in the list, and skips it when another name is', () => {
        for (let seed = 1; seed <= 400; seed++) {
          const bound = generate(seed, 'name');
          expect(onlyConstantExecCalls(bound.line, constantIdentifiers(bound.source)), bound.source).toBe(false);
          const unbound = generate(seed, 'other');
          expect(onlyConstantExecCalls(unbound.line, constantIdentifiers(unbound.source)), unbound.source).toBe(true);
        }
      });
    });
  });
});
