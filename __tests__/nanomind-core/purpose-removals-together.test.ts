/**
 * The purpose check removes a key's characters and URLs together.
 *
 * The credential analyzer reads the declared purpose (with no frontmatter, the
 * first long line) for test, example, documentation, fixture and demo. URLs
 * are removed from it, and so are credential-shaped values. Both removals are
 * computed on the original line and the union is removed, each removed stretch
 * becoming one space, so removing a key's characters only ever takes words
 * away from the purpose.
 *
 * Every key below is drawn at run time from a fixed seed: no credential-shaped
 * literal sits in the repository, and a failing line is the same on every run.
 */

import { describe, it, expect } from 'vitest';
import { mkdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { purposeWordsFoundForTest } from '../../src/nanomind-core/analyzers/credential-analyzer';
import { findCredentialFormatMatch } from '../../src/types/credential-format';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

const SEED = 0x1987;
const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const ALNUM = `${LETTERS}0123456789`;
const B64URL = `${ALNUM}_-`;
/** Placeholder markers and purpose words a drawn body must not spell by chance. */
const AVOID =
  /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE|TEST|DOCUMENTATION|FIXTURE|DEMO/i;

/** mulberry32 from `seed`. */
function rng(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return (t ^ (t >>> 14)) >>> 0;
  };
}

function drawer(seed: number) {
  const next = rng(seed);
  const pick = <T>(items: readonly T[] | string): T => items[next() % items.length] as T;
  /** `n` characters from `alphabet`, led by a letter, spelling nothing in AVOID. */
  const run = (n: number, alphabet = ALNUM): string => {
    for (;;) {
      let s = pick<string>(LETTERS);
      for (let i = 1; i < n; i++) s += pick<string>(alphabet);
      if (!AVOID.test(s)) return s;
    }
  };
  return { next, pick, run };
}

/**
 * The base's purpose-word test, copied from commit 1a8c510081f3
 * (src/nanomind-core/analyzers/credential-analyzer.ts, isDocumentationOrTestContext
 * and URL_IN_PURPOSE), before credential values were removed from the purpose.
 */
const BASE_URL_IN_PURPOSE = /\b[a-z][a-z0-9+.-]*(:\/\/[^\s"<>]*)?/g;
function basePurposeWords(declaredPurpose: string): string[] {
  const purpose = declaredPurpose
    .toLowerCase()
    .replace(BASE_URL_IN_PURPOSE, (run: string, url?: string) => (url === undefined ? run : ' '));
  return ['test', 'example', 'documentation', 'fixture', 'demo'].filter(w => purpose.includes(w));
}

/** Failing finding ids and severities from the real semantic pipeline. */
async function failingFindings(file: string, content: string): Promise<string[]> {
  const dir = tempDir('hma-purpose-together-');
  mkdirSync(dirname(join(dir, file)), { recursive: true });
  await writeFile(join(dir, file), content, 'utf-8');
  const result = await runNanoMindScan(dir, []);
  return result.mergedFindings
    .filter(f => !f.passed)
    .map(f => f.checkId)
    .sort();
}

const d = drawer(SEED);

/**
 * A quoted value: a word character and `_`, then the key, then `://h/test`. A
 * source file is tagged as reading credentials by a canonical vendor key; a
 * config file by the word `credential`, so the JWT and entropy lines are YAML.
 */
const vendorLine = `const openai = "a_sk-${d.run(32)}://h/test";\n`;
const jwtLine = `credential: "a_eyJ${d.run(24, B64URL)}.${d.run(40, B64URL)}.${d.run(43, B64URL)}://h/test"\n`;
/** A 40-character secret glued to underscore filler: the credible window starts inside the filler. */
const entropyRun = `${'_'.repeat(45)}=${d.run(40)}`;
const entropyLine = `credential: "${entropyRun}://h/test"\n`;

describe('a key glued to a URL whose path holds a purpose word is reported, as at the base', () => {
  it('U1: a word character and underscore, a vendor-shaped key, then ://h/test', async () => {
    expect(basePurposeWords(vendorLine)).toEqual([]);
    expect(purposeWordsFoundForTest(vendorLine)).toEqual([]);
    expect(await failingFindings('index.js', vendorLine)).toContain('AST-CRED-001');
  }, 120_000);

  it('U2: the same with a JWT-shaped value', async () => {
    expect(basePurposeWords(jwtLine)).toEqual([]);
    expect(purposeWordsFoundForTest(jwtLine)).toEqual([]);
    expect(await failingFindings('config.yaml', jwtLine)).toContain('AST-CRED-001');
  }, 120_000);

  it('U2: the same with a high-entropy run that begins partway through a longer run', async () => {
    const hit = findCredentialFormatMatch(entropyRun);
    expect(hit).toBeDefined();
    expect(hit!.index).toBeGreaterThan(0);
    expect(hit!.index).toBeLessThan(45);
    expect(basePurposeWords(entropyLine)).toEqual([]);
    expect(purposeWordsFoundForTest(entropyLine)).toEqual([]);
    expect(await failingFindings('config.yaml', entropyLine)).toContain('AST-CRED-001');
  }, 120_000);
});

describe('U3: removing credential values never adds a purpose word', () => {
  const MIXED = (word: string, p: ReturnType<typeof drawer>): string =>
    [...word].map(c => (p.next() % 2 === 0 ? c.toUpperCase() : c)).join('');

  /** One generated key of each known shape. */
  const keys = (p: ReturnType<typeof drawer>): string[] => [
    `sk-${p.run(32)}`,
    `sk-${p.run(48)}`,
    `sk-proj-${p.run(24, `${ALNUM}_-`)}`,
    `sk-ant-api03-${p.run(40, `${ALNUM}_-`)}`,
    `sk_live_${p.run(24)}`,
    `ghp_${p.run(36)}`,
    `github_pat_${p.run(40, `${ALNUM}_`)}`,
    `AKIA${p.run(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`,
    `AIza${p.run(35, `${ALNUM}_-`)}`,
    `xoxb-${p.run(12)}-${p.run(24)}`,
    `eyJ${p.run(20, B64URL)}.${p.run(30, B64URL)}.${p.run(43, B64URL)}`,
    p.run(44, `${ALNUM}+=`),
    `${'_'.repeat(10 + (p.next() % 40))}${p.pick(['=', '+', ''])}${p.run(40)}`,
  ];

  const pieces = (p: ReturnType<typeof drawer>): string[] => [
    p.run(1 + (p.next() % 6), `${ALNUM}_`),
    p.pick(['a', 'x', '_', 'a_', '9', 'Z_']),
    p.pick([' ', '"', "'", '=', '+', '-', '.', '/', ':', '_', '<', '>', ',', '\t']),
    p.pick(keys(p)),
    p.pick(keys(p)),
    '://',
    `://h/${MIXED(p.pick(['test', 'documentation', 'fixture', 'demo', 'example']), p)}`,
    `/${MIXED(p.pick(['test', 'documentation', 'fixture', 'demo', 'example']), p)}/`,
    `${p.pick(['https', 'a', 'x.y', 'S3'])}://${p.run(3)}.${MIXED(p.pick(['test', 'demo', 'fixture', 'documentation']), p)}`,
  ];

  it('for 400 generated lines the words found are a subset of the base words', () => {
    const p = drawer(SEED + 1);
    let withKey = 0;
    for (let n = 0; n < 400; n++) {
      const all = pieces(p);
      const count = 2 + (p.next() % 7);
      let line = '';
      for (let i = 0; i < count; i++) line += p.pick(all);
      if (findCredentialFormatMatch(line) !== undefined) withKey++;
      const base = new Set(basePurposeWords(line));
      const added = purposeWordsFoundForTest(line).filter(w => !base.has(w));
      expect(added, `seed ${SEED + 1}, line ${n}: ${JSON.stringify(line)}`).toEqual([]);
    }
    // The cell is about lines holding keys: most of them do.
    expect(withKey).toBeGreaterThan(200);
  });
});
