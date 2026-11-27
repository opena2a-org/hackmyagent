import { describe, it, expect } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import { HardeningScanner, isMatchInsideStringLiteral } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

/**
 * The string-literal test (`isMatchInsideStringLiteral`) and the two line
 * blankers in front of it walk a line under a step limit. When the scanner
 * cannot tell whether a match is code or text, it reports: no exit at the
 * limit marks the rest of a line as text, and the walk is linear in the
 * line, so a long line of ordinary code is read to its end.
 *
 * Every dropping caller gets a cell of the same shape: padding past the old
 * 100,000-step limit, then real code on the same line.
 */

/** Past the old 100,000-step limit. */
const OVER = 150_000;
/** Below the old limit. */
const UNDER = 99_000;

const stringPad = (n: number): string => `const pad = '${'x'.repeat(n)}'; `;
const commentPad = (n: number): string => `/* ${'x'.repeat(n)} */ `;
const templatePad = (n: number): string => `const pad = \`${'x'.repeat(n)}\`; `;

type Row = [checkId: string, name: string, line: number | undefined, severity: string];

async function nemo(root: string): Promise<any[]> {
  return (new HardeningScanner() as any).checkNemoClawPatterns(root, false);
}

async function failing(root: string, checkId: string): Promise<Row[]> {
  return (await nemo(root))
    .filter((f) => f.checkId === checkId && !f.passed)
    .map((f) => [f.checkId, f.name, f.line, f.severity]);
}

async function project(prefix: string, file: string, text: string): Promise<string> {
  const root = tempDir(prefix);
  await fs.writeFile(path.join(root, file), text);
  return root;
}

const DIGEST_SKIP = 'if (!artifact.digest) return fetchUnverified(artifact);';
const NEMO002: Row = ['NEMO-002', 'Digest verification skipped on falsy value', 1, 'critical'];

describe('NEMO-002 past the old walk limit', () => {
  it('reports a digest skip after a string literal of more than 100,000 characters', async () => {
    const root = await project('limit-n2-str-', 'install.ts', stringPad(OVER) + DIGEST_SKIP + '\n');
    expect(await failing(root, 'NEMO-002')).toEqual([NEMO002]);
  });

  it('reports a digest skip after a block comment of more than 100,000 characters', async () => {
    const root = await project('limit-n2-cmt-', 'install.ts', commentPad(OVER) + DIGEST_SKIP + '\n');
    expect(await failing(root, 'NEMO-002')).toEqual([NEMO002]);
  });

  it('reports a digest skip after a template literal of more than 100,000 characters', async () => {
    const root = await project('limit-n2-tpl-', 'install.ts', templatePad(OVER) + DIGEST_SKIP + '\n');
    expect(await failing(root, 'NEMO-002')).toEqual([NEMO002]);
  });

  it('still does not report the statement inside a real string literal on a short line', async () => {
    const root = await project('limit-n2-short-', 'install.ts', `const s = '${DIGEST_SKIP}';\n`);
    expect(await failing(root, 'NEMO-002')).toEqual([]);
  });

  it('does not report the statement inside a string literal after 150,000 characters of string', async () => {
    const root = await project('limit-n2-quoted-', 'install.ts', stringPad(OVER) + `const s = '${DIGEST_SKIP}';\n`);
    expect(await failing(root, 'NEMO-002')).toEqual([]);
  });
});

const EVAL: Row = ['NEMO-009', 'Unsafe deserialization: eval()', 1, 'critical'];

describe('NEMO-009 TS/JS sites past the old walk limit', () => {
  it('W1: a line padded to 150,000 characters, then a real eval(userInput): exactly one finding', async () => {
    const root = await project('limit-w1-', 'app.ts', stringPad(OVER) + 'eval(userInput);\n');
    expect(await failing(root, 'NEMO-009')).toEqual([EVAL]);
  });

  it('W2: the same with 99,000 characters gives the output of the base, byte for byte', async () => {
    const root = await project('limit-w2-', 'app.ts', stringPad(UNDER) + 'eval(userInput);\n');
    // Pinned from checkNemoClawPatterns on the default branch before this change.
    expect(JSON.stringify(await nemo(root))).toBe(W2_BASE_OUTPUT);
  });

  it('W3: a 150,000-character string, then eval(x) inside a string literal: zero findings', async () => {
    const root = await project('limit-w3-', 'app.ts', stringPad(OVER) + "const s = 'eval(x)';\n");
    expect(await failing(root, 'NEMO-009')).toEqual([]);
  });

  it('reports a real eval after a template literal of more than 100,000 characters', async () => {
    const root = await project('limit-n9-tpl-', 'app.ts', templatePad(OVER) + 'eval(userInput);\n');
    expect(await failing(root, 'NEMO-009')).toEqual([EVAL]);
  });

  it('reports a real indirect eval after 150,000 characters of padding', async () => {
    const root = await project('limit-n9-ind-', 'app.ts', stringPad(OVER) + 'globalThis.eval(userInput);\n');
    expect(await failing(root, 'NEMO-009')).toEqual([
      ['NEMO-009', 'Unsafe deserialization: indirect eval()', 1, 'critical'],
    ]);
  });

  it('reports a real new Function() after 150,000 characters of padding', async () => {
    const root = await project('limit-n9-fn-', 'app.ts', stringPad(OVER) + 'const f = new Function(body);\n');
    expect(await failing(root, 'NEMO-009')).toEqual([
      ['NEMO-009', 'Unsafe deserialization: new Function()', 1, 'critical'],
    ]);
  });

  it('reports a real JSON5.parse after 150,000 characters of padding', async () => {
    const root = await project('limit-n9-json5-', 'app.ts', stringPad(OVER) + 'const cfg = JSON5.parse(text);\n');
    expect(await failing(root, 'NEMO-009')).toEqual([
      ['NEMO-009', 'Unsafe deserialization: JSON5.parse', 1, 'high'],
    ]);
  });
});

describe('LOG-002 past the old walk limit', () => {
  it('reports a real console.log(password) after 150,000 characters of padding', async () => {
    const root = await project('limit-log2-', 'server.ts', stringPad(OVER) + 'console.log(password);\n');
    const drafts: any[] = await (new HardeningScanner() as any).checkLoggingSecurity(root, false);
    expect(
      drafts
        .filter((f) => f.checkId === 'LOG-002' && !f.passed)
        .map((f) => [f.checkId, f.file, f.line, f.severity]),
    ).toEqual([['LOG-002', 'server.ts', 1, 'high']]);
  });
});

describe('the predicate on a long line', () => {
  it('answers by the line itself, not by how far into it the match sits', () => {
    const line = stringPad(OVER) + "eval(userInput); const s = 'eval(x)';";
    expect(isMatchInsideStringLiteral(line, line.indexOf('eval(userInput)'))).toBe(false);
    expect(isMatchInsideStringLiteral(line, line.indexOf('eval(x)'))).toBe(true);
  });

  it('a long line with many forking slashes is read to its end within 10 seconds', () => {
    // Six undecidable slashes (`}` then `/`) fork the walk into 64 lexings,
    // each of which reads the 1,000,000-character tail; the trailing ones
    // past the fork budget stop branching. The bound is generous on purpose.
    const tail = 'a = b + c; '.repeat(Math.ceil(1_000_000 / 11));
    const line = '} /a/ '.repeat(6) + tail + '} /a/ '.repeat(10_000) + "eval(p); 'eval(q)'";
    const t0 = performance.now();
    const real = isMatchInsideStringLiteral(line, line.indexOf('eval(p)'));
    const elapsed = performance.now() - t0;
    expect(real).toBe(false);
    expect(elapsed).toBeLessThan(10_000);
  });
});

const W2_BASE_OUTPUT =
  '[{"checkId":"NEMO-002","name":"Blueprint/artifact digest verification gap",' +
  '"description":"No empty digest fields or digest-skip logic found.",' +
  '"category":"nemo-integrity","severity":"critical","passed":true,' +
  '"message":"No digest verification gaps detected","fixable":false,' +
  '"guidance":"Empty or missing digest fields bypass integrity verification,' +
  ' allowing tampered artifacts to pass through the supply chain unchecked."},' +
  '{"checkId":"NEMO-003","name":"Hot-reload policy paths reachable from user input",' +
  '"description":"No policy reload paths reachable from user input found.",' +
  '"category":"nemo-policy","severity":"high","passed":true,' +
  '"message":"No unsafe policy reload paths detected","fixable":false,' +
  '"guidance":"User-reachable policy reload paths allow attackers to modify security policies via crafted requests,' +
  ' potentially disabling protections at runtime."},{"checkId":"NEMO-004",' +
  '"name":"API key passed as CLI argument",' +
  '"description":"No credentials passed as CLI arguments detected.",' +
  '"category":"nemo-secrets","severity":"high","passed":true,' +
  '"message":"No CLI credential exposure detected","fixable":false,' +
  '"guidance":"CLI arguments are visible in process listings (ps aux), shell history,' +
  ' and log files. Environment variables and stdin keep credentials out of these surfaces."},' +
  '{"checkId":"NEMO-005","name":"exec() with user-controlled string interpolation",' +
  '"description":"No exec() calls with user-controlled string interpolation found.",' +
  '"category":"nemo-injection","severity":"critical","passed":true,' +
  '"message":"No command injection via exec() detected","fixable":false,' +
  '"guidance":"exec() passes strings to /bin/sh,' +
  ' which interprets shell metacharacters. User-controlled interpolation in exec() enables arbitrary command execution."},' +
  '{"checkId":"NEMO-007","name":"Full process.env passthrough to subprocess",' +
  '"description":"No full process.env passthrough to subprocesses found.",' +
  '"category":"nemo-secrets","severity":"high","passed":true,' +
  '"message":"No process.env leakage to subprocesses detected","fixable":false,' +
  '"guidance":"Spreading process.env leaks all environment variables (including API keys and tokens) to child processes. Use an explicit allowlist of only needed variables."},' +
  '{"checkId":"NEMO-008","name":"TOCTOU race between verify and apply",' +
  '"description":"No verify/apply TOCTOU patterns detected.","category":"nemo-integrity",' +
  '"severity":"high","passed":true,"message":"No TOCTOU race conditions detected",' +
  '"fixable":false,"guidance":"When verify and execute are separate steps,' +
  ' an attacker can swap the artifact between verification and use. Atomic verify-then-execute eliminates this race window."},' +
  '{"checkId":"NEMO-009","name":"Unsafe deserialization: eval()",' +
  '"description":"eval() executes arbitrary JavaScript code. If the input comes from untrusted sources,' +
  ' this enables code injection.","category":"nemo-deserialization","severity":"critical",' +
  '"passed":false,"message":"eval() at line 1","fixable":false,"file":"app.ts","line":1,' +
  '"fix":"Use JSON.parse() for data, or a sandboxed evaluator for expressions.",' +
  '"guidance":"eval() executes arbitrary JavaScript. If the string comes from user input,' +
  ' network data, or files, an attacker can inject any code."}]';
