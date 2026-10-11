/**
 * #999 — the Fix commands the steganography checks print run as written.
 *
 * UNICODE-STEGO-003 spliced `JSON.stringify(path)` into a double-quoted
 * `node -e` argument, so the path's quotes closed the shell's and pasting the
 * command for `eval-hidden.js` failed with `ReferenceError: hidden is not
 * defined`. UNICODE-STEGO-001 and -004 built `xxd` + the quoted path, and the
 * renderer escapes the line for display, so for a file whose NAME carries an
 * invisible code point the printed command named a file that does not exist:
 * `xxd 'benign\u{e0041}evil.js'`.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { escapeForDisplay } from '../../src/ui/display-safe';
import { tempDir } from '../helpers/temp-dir';

const ZWSP = Buffer.from([0xe2, 0x80, 0x8b]); // U+200B
const TAG_0001 = Buffer.from([0xf3, 0xa0, 0x80, 0x81]); // U+E0001
const HIDDEN_NAME = `benign${String.fromCodePoint(0xe0041)}evil.js`;

describe('UNICODE-STEGO Fix commands (#999)', () => {
  let dir: string;

  beforeEach(async () => {
    dir = tempDir('hma-stego-fix-');
    await fs.writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  async function finding(checkId: string, file: string): Promise<SecurityFinding> {
    const result = await new HardeningScanner().scan({ targetDir: dir });
    const hit = result.findings.find((f) => f.checkId === checkId && f.file === file && !f.passed);
    expect(hit, `${checkId} did not fire on ${file}`).toBeDefined();
    return hit!;
  }

  it('UNICODE-STEGO-003: the printed command runs and lists the hidden code points', async () => {
    const payload = Buffer.concat(Array.from({ length: 40 }, () => Buffer.from([0xef, 0xb8, 0x80]))); // U+FE00 x40
    await fs.writeFile(path.join(dir, 'eval-hidden.js'), Buffer.concat([Buffer.from("eval('"), payload, Buffer.from("');\n")]));

    const f = await finding('UNICODE-STEGO-003', 'eval-hidden.js');
    const printed = escapeForDisplay(f.fix ?? '');
    expect(printed).toMatch(/^node -e '/);
    const run = spawnSync('/bin/sh', ['-c', printed], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ''}` },
    });
    expect(run.stderr).not.toMatch(/ReferenceError/);
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("'fe00'");
  });

  it('UNICODE-STEGO-003: a path with a quote or a space is an argument, not script text', async () => {
    const payload = Buffer.concat(Array.from({ length: 40 }, () => Buffer.from([0xef, 0xb8, 0x80])));
    const name = `it's here.js`;
    await fs.writeFile(path.join(dir, name), Buffer.concat([Buffer.from("eval('"), payload, Buffer.from("');\n")]));

    const f = await finding('UNICODE-STEGO-003', name);
    const run = spawnSync('/bin/sh', ['-c', escapeForDisplay(f.fix ?? '')], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ''}` },
    });
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("'fe00'");
  });

  it('UNICODE-STEGO-001: a plain name gets the xxd command', async () => {
    await fs.writeFile(path.join(dir, 'plain.js'), Buffer.concat([Buffer.from('const a = "x'), ZWSP, Buffer.from('";\n')]));
    const f = await finding('UNICODE-STEGO-001', 'plain.js');
    expect(f.fix).toBe('xxd plain.js | grep -iE "e280[8-9a-e]|efbb|efb8|f3a0"');
  });

  it('UNICODE-STEGO-001: a name carrying an invisible code point gets no command naming a different file', async () => {
    await fs.writeFile(path.join(dir, HIDDEN_NAME), Buffer.concat([Buffer.from('const a = "x'), ZWSP, Buffer.from('";\n')]));
    const f = await finding('UNICODE-STEGO-001', HIDDEN_NAME);
    const printed = escapeForDisplay(f.fix ?? '');
    expect(printed).not.toMatch(/xxd/);
    expect(printed).not.toContain('\\u{e0041}');
    expect(printed).toMatch(/cannot be shown truthfully/);
  });

  it('UNICODE-STEGO-004: the title names what the check reports, and a hidden name gets no command', async () => {
    await fs.writeFile(path.join(dir, 'tag-block.js'), Buffer.concat([Buffer.from('const z = "t'), TAG_0001, Buffer.from('";\n')]));
    const plain = await finding('UNICODE-STEGO-004', 'tag-block.js');
    expect(plain.name).toBe('Invisible Plane-14 Characters Detected');
    expect(plain.fix).toBe('xxd tag-block.js | grep "f3a0"');

    await fs.rm(path.join(dir, 'tag-block.js'));
    const hidden = `tag${String.fromCodePoint(0xe0041)}block.js`;
    await fs.writeFile(path.join(dir, hidden), Buffer.concat([Buffer.from('const z = "t'), TAG_0001, Buffer.from('";\n')]));
    const f = await finding('UNICODE-STEGO-004', hidden);
    const printed = escapeForDisplay(f.fix ?? '');
    expect(printed).not.toMatch(/xxd/);
    expect(printed).toMatch(/cannot be shown truthfully/);
  });
});
