/**
 * #377 — the finding header names the file the `Verify:` line names: the FULL
 * relative path. `shortenPath` kept only the last two segments and returned
 * the result indistinguishable from a genuinely two-segment path, so in any
 * tree three-plus segments deep the header could name a different real file
 * than the one the finding is about (`packages/a/src/config/db.json` and
 * `packages/b/src/config/db.json` both rendered `config/db.json`).
 *
 * The credential key below is synthesized at run time from a fixed seed and
 * written into a temp directory, never committed: the detector skips any
 * value carrying the house FAKE/PLACEHOLDER markers, and committing a
 * credential-shaped literal to a public repo is worse. Same convention and
 * constraints as locatable-runnable-citations.test.ts: 48+ consecutive
 * alphanumerics after `sk-`, no placeholder marker anywhere in the key bytes,
 * no fixture/test/example directory segment in the fixture path.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

function syntheticKey(): string {
  const alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let seed = 42;
  let body = '';
  for (let i = 0; i < 52; i++) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    body += alpha[seed % alpha.length];
  }
  return `sk-${body}`;
}

function run(args: string[]): string {
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
  return String(r.stdout ?? '') + String(r.stderr ?? '');
}

let root: string;
const DEEP = 'packages/api/src/config.ts';

beforeAll(() => {
  assertDistFresh();
  root = mkdtempSync(path.join(tmpdir(), 'hma-377-'));
  mkdirSync(path.join(root, 'deep', path.dirname(DEEP)), { recursive: true });
  writeFileSync(path.join(root, 'deep', DEEP), `export const apiKey = "${syntheticKey()}";\n`);
  mkdirSync(path.join(root, 'shallow', 'src'), { recursive: true });
  writeFileSync(path.join(root, 'shallow', 'src', 'config.ts'), `export const apiKey = "${syntheticKey()}";\n`);
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('finding headers carry the full relative path (#377)', () => {
  it('a depth-3 finding header names the path the Verify line cites', () => {
    const out = run(['secure', path.join(root, 'deep')]);
    expect(out).toContain(`│ ${DEEP}:1`);
    // never the old two-segment elision as the whole header path
    expect(out).not.toMatch(/│ src\/config\.ts:1/);
    // header/Verify agreement: the Verify citation carries the same path
    const verify = out.split('\n').find((l) => l.includes('Verify:') && l.includes('config.ts'));
    expect(verify).toBeDefined();
    expect(verify as string).toContain(DEEP);
  });

  it('a two-segment path renders unchanged', () => {
    const out = run(['secure', path.join(root, 'shallow')]);
    expect(out).toContain('│ src/config.ts:1');
  });

  it('the collapse line escapes the artifact name it renders', () => {
    // Two same-name findings in one directory make the second collapse into
    // `+ 1 more <severity> in <artifactName>`; the shown finding's file name
    // carries a real newline plus a forged severity line. Escaped, the token
    // renders as a visible \n mid-line; unescaped, it starts a line of its
    // own — the #324 harm class, proven live in adversarial review.
    const forged = 'FORGED-COLLAPSE-LINE.ts';
    const dir = path.join(root, 'collapse', 'src');
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'a\n' + forged), `export const k1 = "${syntheticKey()}";\n`);
    writeFileSync(path.join(dir, 'zz-sibling.ts'), `export const k2 = "${syntheticKey()}";\n`);
    const out = run(['secure', path.join(root, 'collapse')]);
    expect(out).toContain(forged);
    for (const line of out.split('\n')) {
      expect(line.startsWith(forged)).toBe(false);
    }
  });
});
