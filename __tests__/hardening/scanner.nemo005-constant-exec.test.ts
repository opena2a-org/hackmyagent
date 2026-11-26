import { describe, it, expect, beforeEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { constantIdentifiers, onlyConstantExecCalls } from '../../src/hardening/constant-exec';
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
});
