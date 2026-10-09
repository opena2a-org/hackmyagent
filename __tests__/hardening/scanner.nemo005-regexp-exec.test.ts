import { describe, it, expect, beforeEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { onlyRegExpExecCalls, regExpIdentifiers } from '../../src/hardening/regexp-exec';
import * as fs from 'fs/promises';
import * as path from 'path';
import { tempDir } from '../helpers/temp-dir';

// NEMO-005 reports exec() with an interpolated template literal as command
// injection. RegExp.prototype.exec shares the name but runs a pattern match,
// so a regular-expression receiver must not be reported, while a
// child_process exec with the same interpolation still is.
describe('NEMO-005 RegExp.exec false positive', () => {
  let scanner: HardeningScanner;
  let dir: string;

  beforeEach(() => {
    scanner = new HardeningScanner();
    dir = tempDir('hma-nemo005-');
  });

  async function nemo005(fileName: string, source: string) {
    await fs.writeFile(path.join(dir, fileName), source);
    const result = await scanner.scan({ targetDir: dir });
    return result.findings.filter((f) => f.checkId === 'NEMO-005' && !f.passed);
  }

  describe('regular-expression receivers are not reported', () => {
    it('new RegExp built from a template literal, then .exec()', async () => {
      const js = [
        'function field(block, name) {',
        "  const m = new RegExp(`^${name}:\\\\s*(.*)$`, 'm').exec(block);",
        '  return m ? m[1] : null;',
        '}',
      ].join('\n');
      expect(await nemo005('parse.js', js)).toHaveLength(0);
    });

    it('new RegExp whose pattern carries escaped parentheses', async () => {
      const ts = "const m = new RegExp(`^const ${name} = new Set\\\\(\\\\[([^\\\\]]*)\\\\]\\\\);$`, 'm').exec(src);";
      expect(await nemo005('sets.ts', ts)).toHaveLength(0);
    });

    it('regex literal receiver with an interpolated argument', async () => {
      const ts = 'const m = /^v(\\d+)$/.exec(`${input}`);';
      expect(await nemo005('version.ts', ts)).toHaveLength(0);
    });

    it('identifier declared from new RegExp', async () => {
      const ts = [
        'const re = new RegExp(`${name}=(\\\\w+)`);',
        'const m = re.exec(`${input}`);',
      ].join('\n');
      expect(await nemo005('kv.ts', ts)).toHaveLength(0);
    });

    it('identifier declared from a regex literal, called with optional chaining', async () => {
      const ts = [
        'export const ID_RE = /^[a-z]+$/;',
        'const m = ID_RE?.exec(`${id}`);',
      ].join('\n');
      expect(await nemo005('ids.ts', ts)).toHaveLength(0);
    });
  });

  describe('command execution is still reported', () => {
    it('child_process exec with an interpolated string keeps file, line and fix', async () => {
      const js = [
        "const { exec } = require('child_process');",
        'function run(name) {',
        '  exec(`git log --author=${name}`);',
        '}',
      ].join('\n');
      const hits = await nemo005('run.js', js);
      expect(hits).toHaveLength(1);
      expect(hits[0].severity).toBe('critical');
      expect(hits[0].file).toBe('run.js');
      expect(hits[0].line).toBe(3);
      expect(hits[0].fix).toMatch(/execFile\(\) or spawn\(\)/);
    });

    it('child_process.exec member call', async () => {
      const ts = 'child_process.exec(`ls ${input}`);';
      expect(await nemo005('ls.ts', ts)).toHaveLength(1);
    });

    it('execSync is never treated as a RegExp method', async () => {
      const ts = 'const out = execSync(`npm view ${name}`);';
      expect(await nemo005('view.ts', ts)).toHaveLength(1);
    });

    it('a shell exec on the same line as a RegExp exec', async () => {
      const ts = 'if (new RegExp(`${name}`).exec(s)) cp.exec(`rm ${name}`);';
      expect(await nemo005('mixed.ts', ts)).toHaveLength(1);
    });

    it('an identifier that is also assigned from child_process', async () => {
      // The reassignment line names no import or require, so only the
      // assignment rule can drop `runner` from the regular expressions.
      const js = [
        "const cp = require('child_process');",
        'let runner = /x/;',
        'runner = cp;',
        'runner.exec(`ls ${name}`);',
      ].join('\n');
      expect(await nemo005('reassigned.js', js)).toHaveLength(1);
    });

    it('an identifier reassigned on a require line', async () => {
      const js = [
        'let runner = /x/;',
        "runner = require('child_process');",
        'runner.exec(`ls ${name}`);',
      ].join('\n');
      expect(await nemo005('required.js', js)).toHaveLength(1);
    });

    it('an identifier bound by an import, even when a local shadows it with a regex', async () => {
      const ts = [
        "import * as cp from 'child_process';",
        'function check(s) {',
        '  const cp = /^ok$/;',
        '  return cp.test(s);',
        '}',
        'cp.exec(`ls ${name}`);',
      ].join('\n');
      expect(await nemo005('imported.ts', ts)).toHaveLength(1);
    });

    it('a member receiver the file never declares', async () => {
      const ts = 'this.shell.exec(`deploy ${name}`);';
      expect(await nemo005('member.ts', ts)).toHaveLength(1);
    });
  });

  describe('regExpIdentifiers', () => {
    it('40,000 regex declarations resolve in linear time', () => {
      const file = (n: number) =>
        Array.from({ length: n }, (_, i) => `let a${i} = /x/;`).join('\n') +
        '\nconst m = a0.exec(`${name}`);\n';
      const small = file(10_000);
      const large = file(40_000);
      const time = (src: string) => {
        let best = Infinity;
        for (let r = 0; r < 3; r++) {
          const t0 = performance.now();
          regExpIdentifiers(src);
          best = Math.min(best, performance.now() - t0);
        }
        return best;
      };
      time(small); // warm-up
      const tSmall = time(small);
      const tLarge = time(large);
      console.log(
        `#878 regExpIdentifiers: 10,000 declarations (${small.length} bytes) ${tSmall.toFixed(1)}ms; ` +
          `40,000 declarations (${large.length} bytes) ${tLarge.toFixed(1)}ms`,
      );
      expect(regExpIdentifiers(large).size).toBe(40_000);
      // 4x the input: a linear pass is ~4x; a rescan of the file per identifier was ~16x.
      // The floor keeps sub-millisecond noise from failing the ratio.
      expect(tLarge).toBeLessThan(Math.max(tSmall * 8, 50));
      expect(tLarge).toBeLessThan(2_000);
    });

    it('sees an assignment that starts inside another assignment\'s type annotation', () => {
      const content = [
        'let re = /x/;',
        'const x: typeof re = build();',
      ].join('\n');
      expect(regExpIdentifiers(content).has('re')).toBe(false);
    });

    it('drops an identifier later assigned something other than a regular expression', () => {
      const content = ['let runner = /x/;', 'runner = cp;'].join('\n');
      expect(regExpIdentifiers(content).has('runner')).toBe(false);
    });
  });

  describe('onlyRegExpExecCalls', () => {
    it('rejects a RegExp call that is not the receiver', () => {
      expect(onlyRegExpExecCalls('foo(new RegExp(`${name}`)).exec(`${x}`)', new Set())).toBe(false);
    });

    it('rejects execSync even on a regular-expression receiver', () => {
      expect(onlyRegExpExecCalls('re.execSync(`${name}`);', new Set(['re']))).toBe(false);
      expect(onlyRegExpExecCalls('/x/.execSync(`${name}`);', new Set())).toBe(false);
      expect(onlyRegExpExecCalls('new RegExp(`${name}`).execSync(s);', new Set())).toBe(false);
    });

    it('accepts a const annotated RegExp', () => {
      const content = 'const re: RegExp = build();\nre.exec(`${name}`);';
      const idents = regExpIdentifiers(content);
      expect(idents.has('re')).toBe(true);
      expect(onlyRegExpExecCalls('re.exec(`${name}`);', idents)).toBe(true);
    });
  });
});
