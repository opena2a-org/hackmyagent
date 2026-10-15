import { describe, it, expect } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

/**
 * NEMO-008 pairs a verify line with an exec line in another file of the same
 * directory. On a TypeScript package compiled with tsc it paired two lines
 * that are neither:
 *
 *   - the barrel's CommonJS export list, `exports.validateToken = ...
 *     = exports.hashName = void 0;`, where the verify chain `validate.*hash`
 *     matched across two exported names; and
 *   - a regular expression's `.exec(text)` in a sibling test file, which is
 *     RegExp.prototype.exec, not process execution.
 *
 * An export or import list is no longer a verify site, and a `.exec(` method
 * call is an exec site only in a file that imports child_process. A bare
 * `exec(`, and `spawn(`, `execSync(` and `execFile(`, count as before.
 */

async function writeFile(root: string, rel: string, body: string): Promise<void> {
  await fs.mkdir(path.dirname(path.join(root, rel)), { recursive: true });
  await fs.writeFile(path.join(root, rel), body);
}

async function nemo008(root: string): Promise<Array<[string, number]>> {
  const drafts: any[] = await (new HardeningScanner() as any).checkNemoClawPatterns(root, false);
  return drafts
    .filter((f) => f.checkId === 'NEMO-008' && !f.passed)
    .map((f) => [f.file, f.line]);
}

const BARREL = [
  '"use strict";',
  'Object.defineProperty(exports, "__esModule", { value: true });',
  'exports.validateToken = exports.formatDate =exports.hashName = void 0;',
  'var token_1 = require("./token");',
  '',
].join('\n');

const REGEX_EXEC = [
  '"use strict";',
  'function majorOf(text) {',
  '  const match = /^v?(\\d+)\\./.exec(text);',
  '  return match ? Number(match[1]) : null;',
  '}',
  '',
].join('\n');

const VERIFY = [
  "const fs = require('fs');",
  'function check(file, digest) {',
  "  if (!verify(file, digest)) throw new Error('digest mismatch');",
  '}',
  '',
].join('\n');

const EXEC_FILE = [
  "const { execFile } = require('child_process');",
  'function apply(file) {',
  '  execFile(file);',
  '}',
  '',
].join('\n');

describe('NEMO-008 on compiled export lists and regular-expression exec calls', () => {
  it('reports nothing for a compiled export list beside a regular-expression exec call', async () => {
    const root = tempDir('nemo008-barrel-');
    await writeFile(root, 'dist-test/index.js', BARREL);
    await writeFile(root, 'dist-test/version.test.js', REGEX_EXEC);
    expect(await nemo008(root)).toEqual([]);
  });

  it('still reports verify(file, digest) beside a child_process execFile call, at the verify line', async () => {
    const root = tempDir('nemo008-positive-');
    await writeFile(root, 'lib/verify.js', VERIFY);
    await writeFile(root, 'lib/apply.js', EXEC_FILE);
    expect(await nemo008(root)).toEqual([[path.join('lib', 'verify.js'), 3]]);
  });

  it.each([
    ['a compiled export list', 'exports.validateToken = exports.hashName = void 0;'],
    ['a one-name compiled export list', 'exports.validateFileHash = void 0;'],
    ['an export list', 'export { validateToken, hashName };'],
    ['a type export list', 'export type { ValidateOptions, HashResult };'],
    ['an import ... from line', "import { validateToken, hashName } from './lib';"],
    ['an export ... from line', 'export { validateToken, hashName } from "./lib";'],
    ['a namespace import', "import * as validateHashing from './lib';"],
    ['module.exports = {', 'module.exports = { validateToken, hashName };'],
    ['an opening module.exports = { line', 'module.exports = { validateToken, hashName,'],
  ])('%s is not a verify site', async (_name, line) => {
    const root = tempDir('nemo008-list-');
    await writeFile(root, 'src/index.js', `${line}\n`);
    await writeFile(root, 'src/apply.js', EXEC_FILE);
    expect(await nemo008(root)).toEqual([]);
  });

  it.each([
    ['module.exports holding a call', 'module.exports = { ok: validateHash(file) };'],
    ['an export list followed by a call', 'export { validateToken }; validateHash(file);'],
    ['an import followed by a call', "import { a } from './lib'; validateHash(file);"],
    ['an exports assignment of a call', 'exports.ok = exports.validateHash = check(file);'],
  ])('%s is still a verify site', async (_name, line) => {
    const root = tempDir('nemo008-list-call-');
    await writeFile(root, 'src/index.js', `${line}\n`);
    await writeFile(root, 'src/apply.js', EXEC_FILE);
    expect(await nemo008(root)).toEqual([[path.join('src', 'index.js'), 1]]);
  });

  it('does not pair a verify call with a regular-expression exec call in a file without child_process', async () => {
    const root = tempDir('nemo008-regex-exec-');
    await writeFile(root, 'lib/verify.js', VERIFY);
    await writeFile(root, 'lib/semver.js', REGEX_EXEC);
    expect(await nemo008(root)).toEqual([]);
  });

  it.each([
    ["const cp = require('child_process');"],
    ['const cp = require("node:child_process");'],
    ["import * as cp from 'child_process';"],
    ['import * as cp from "node:child_process";'],
  ])('a .exec( method call counts in a file that imports child_process: %s', async (importLine) => {
    const root = tempDir('nemo008-cp-exec-');
    await writeFile(root, 'lib/verify.js', VERIFY);
    await writeFile(root, 'lib/apply.js', `${importLine}\nfunction apply(cmd) {\n  cp.exec(cmd);\n}\n`);
    expect(await nemo008(root)).toEqual([[path.join('lib', 'verify.js'), 3]]);
  });

  it('a bare exec( call counts as before, in a file without a child_process import', async () => {
    const root = tempDir('nemo008-bare-exec-');
    await writeFile(root, 'lib/verify.js', VERIFY);
    await writeFile(root, 'lib/apply.js', 'function apply(cmd) {\n  exec(cmd);\n}\n');
    expect(await nemo008(root)).toEqual([[path.join('lib', 'verify.js'), 3]]);
  });

  // An unclosed list line that matches the verify chain and ends in a long
  // run of spaces before a character outside the list class. The first
  // export-list regex backtracked over that run from three quantifiers at
  // once: the scan of one such 10 KB line took minutes.
  it.each([
    ['an unclosed export list', 'export {verify digest'],
    ['an unclosed module.exports list', 'module.exports = {verify digest'],
  ])('%s with ten thousand trailing spaces is scanned in bounded time', async (_name, head) => {
    const root = tempDir('nemo008-long-line-');
    await writeFile(root, 'lib.js', `${head}${' '.repeat(10_000)}(\n`);
    const started = Date.now();
    const found = await nemo008(root);
    const elapsedMs = Date.now() - started;
    expect(found).toEqual([]);
    expect(elapsedMs).toBeLessThan(5_000);
  }, 60_000);
});
