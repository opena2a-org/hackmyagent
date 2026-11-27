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
 * The purpose the analyzer holds has been through the report redaction table,
 * whose markers end in a bracket: a key glued to a URL tail loses the URL's
 * scheme to the marker. The compiler finds the URLs on the text as written and
 * hands their positions in the redacted purpose to the analyzer, so each cell
 * below holds both on the line as written and on the line through the table.
 *
 * Every key below is drawn at run time: no credential-shaped literal sits in
 * the repository. Each run draws a new seed and prints it; HMA_TEST_SEED=<seed>
 * replays that run. Every case draws from its own stream, made from the seed
 * and the case's index, so a case draws the same line when it runs alone, and
 * a failure names the seed and the case.
 */

import { describe, it, expect } from 'vitest';
import { createHash, randomInt } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { purposeWordsFoundForTest } from '../../src/nanomind-core/analyzers/credential-analyzer';
import { declaredPurposeForTest } from '../../src/nanomind-core/compiler/semantic-compiler';
import { findCredentialFormatMatch } from '../../src/types/credential-format';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import {
  redactSecretsForReport,
  redactSecretsForReportWithOrigins,
} from '../../src/nanomind-core/security/defense-in-depth';
import { tempDir } from '../helpers/temp-dir';

/** The run's seed: HMA_TEST_SEED when set, otherwise a new one for this run. */
function runSeed(): number {
  const given = process.env.HMA_TEST_SEED;
  if (given === undefined || given.trim() === '') return randomInt(0, 2 ** 32);
  const seed = Number(given);
  if (!Number.isInteger(seed) || seed < 0 || seed >= 2 ** 32) {
    throw new Error(`HMA_TEST_SEED must be an integer from 0 to 4294967295, got ${JSON.stringify(given)}`);
  }
  return seed;
}
const SEED = runSeed();
process.stdout.write(`__tests__/nanomind-core/purpose-removals-together.test.ts seed: HMA_TEST_SEED=${SEED}\n`);

/** The seed of case `index`'s own stream. */
function caseSeed(index: number): number {
  return createHash('sha256').update(`${SEED}:${index}`).digest().readUInt32BE(0);
}

/** How a failure names its case: the seed and the case's index. */
const caseName = (index: number) => `seed ${SEED}, case ${index}`;

/** Runs case `index`; a failure's message is led by the seed and the case's index. */
function generatedCase<T>(index: number, run: () => T): T {
  const named = (error: unknown): unknown => {
    if (error instanceof Error) error.message = `${caseName(index)}: ${error.message}`;
    return error;
  };
  let result: T;
  try {
    result = run();
  } catch (error) {
    throw named(error);
  }
  if (result instanceof Promise) {
    return result.catch((error: unknown) => {
      throw named(error);
    }) as T;
  }
  return result;
}
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

/** The purpose words found in `line` once the compiler has taken it through the report redaction table. */
function tablePurposeWords(line: string): string[] {
  const { text, urlSpans } = declaredPurposeForTest(line);
  return purposeWordsFoundForTest(text, urlSpans);
}

/** Failing finding ids from the real semantic pipeline. */
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

/** Cases 0 to 3 are the four lines below, each drawn from its own stream. */
const VENDOR_CASE = 0;
const VENDOR48_CASE = 1;
const JWT_CASE = 2;
const ENTROPY_CASE = 3;

/**
 * A quoted value: a word character and `_`, then the key, then `://h/test`. A
 * source file is tagged as reading credentials by a canonical vendor key; a
 * config file by the word `credential`, so the JWT and entropy lines are YAML.
 */
const vendorLine = `const openai = "a_sk-${drawer(caseSeed(VENDOR_CASE)).run(32)}://h/test";\n`;
const vendorLine48 = `const openai = "a_sk-${drawer(caseSeed(VENDOR48_CASE)).run(48)}://h/test";\n`;
/**
 * The JWT's segments draw from the base64url alphabet, `_` included, and
 * whether the base read the URL tail as a URL depends on the characters
 * drawn: about four draws in ten fall outside this cell, with the base
 * finding the word as well. Every line drawn is kept: the ones outside the
 * cell are held to U3's property, and the first one inside it is `jwtLine`.
 */
const jwtLines: string[] = [];
{
  const p = drawer(caseSeed(JWT_CASE));
  do {
    jwtLines.push(`credential: "a_eyJ${p.run(24, B64URL)}.${p.run(40, B64URL)}.${p.run(43, B64URL)}://h/test"\n`);
  } while (basePurposeWords(jwtLines[jwtLines.length - 1]).length > 0);
}
const jwtLine = jwtLines[jwtLines.length - 1];
/** A 40-character secret glued to underscore filler: the credible window starts inside the filler. */
const entropyRun = `${'_'.repeat(45)}=${drawer(caseSeed(ENTROPY_CASE)).run(40)}`;
const entropyLine = `credential: "${entropyRun}://h/test"\n`;

describe('a key glued to a URL whose path holds a purpose word is reported, as at the base', () => {
  it('U1: a word character and underscore, a 32-character sk- key, then ://h/test', async () => {
    await generatedCase(VENDOR_CASE, async () => {
      expect(basePurposeWords(vendorLine)).toEqual([]);
      expect(purposeWordsFoundForTest(vendorLine)).toEqual([]);
      expect(declaredPurposeForTest(vendorLine).text).toContain('[REDACTED_OPENAI_KEY]://h/test');
      expect(tablePurposeWords(vendorLine)).toEqual([]);
      const found = await failingFindings('index.js', vendorLine);
      expect(found).toContain('AST-CRED-001');
      expect(found).toContain('AST-CRED-003');
    });
  }, 120_000);

  it('U1: the same with a 48-character sk- key', async () => {
    await generatedCase(VENDOR48_CASE, async () => {
      expect(basePurposeWords(vendorLine48)).toEqual([]);
      expect(purposeWordsFoundForTest(vendorLine48)).toEqual([]);
      expect(declaredPurposeForTest(vendorLine48).text).toContain('[REDACTED_OPENAI_KEY]://h/test');
      expect(tablePurposeWords(vendorLine48)).toEqual([]);
      const found = await failingFindings('index.js', vendorLine48);
      expect(found).toContain('AST-CRED-001');
      expect(found).toContain('AST-CRED-003');
    });
  }, 120_000);

  it('U2: the same with a JWT-shaped value', async () => {
    await generatedCase(JWT_CASE, async () => {
      // Lines drawn before it, outside the cell: no word is added to the base's.
      for (const line of jwtLines.slice(0, -1)) {
        const base = new Set(basePurposeWords(line));
        expect(purposeWordsFoundForTest(line).filter(w => !base.has(w)), JSON.stringify(line)).toEqual([]);
        expect(tablePurposeWords(line).filter(w => !base.has(w)), `through the table, ${JSON.stringify(line)}`).toEqual([]);
      }
      expect(basePurposeWords(jwtLine)).toEqual([]);
      expect(purposeWordsFoundForTest(jwtLine)).toEqual([]);
      expect(tablePurposeWords(jwtLine)).toEqual([]);
      const found = await failingFindings('config.yaml', jwtLine);
      expect(found).toContain('AST-CRED-001');
      expect(found).toContain('AST-CRED-003');
    });
  }, 120_000);

  it('U2: the same with a high-entropy run that begins partway through a longer run', async () => {
    await generatedCase(ENTROPY_CASE, async () => {
      const hit = findCredentialFormatMatch(entropyRun);
      expect(hit).toBeDefined();
      expect(hit!.index).toBeGreaterThan(0);
      expect(hit!.index).toBeLessThan(45);
      expect(basePurposeWords(entropyLine)).toEqual([]);
      expect(purposeWordsFoundForTest(entropyLine)).toEqual([]);
      expect(tablePurposeWords(entropyLine)).toEqual([]);
      const found = await failingFindings('config.yaml', entropyLine);
      expect(found).toContain('AST-CRED-001');
      expect(found).toContain('AST-CRED-003');
    });
  }, 120_000);
});

/** U3's lines are cases 4 to 403; the origin map's inputs are case 404. */
const LINES = 400;
const FIRST_LINE_CASE = 4;
const ORIGIN_CASE = FIRST_LINE_CASE + LINES;

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

  it('for 400 generated lines the words found are a subset of the base words, as written and through the table', () => {
    let withKey = 0;
    let redacted = 0;
    for (let n = 0; n < LINES; n++) {
      // Line n is case FIRST_LINE_CASE + n, drawn from its own stream.
      const index = FIRST_LINE_CASE + n;
      const p = drawer(caseSeed(index));
      const all = pieces(p);
      const count = 2 + (p.next() % 7);
      let line = '';
      for (let i = 0; i < count; i++) line += p.pick(all);
      if (findCredentialFormatMatch(line) !== undefined) withKey++;
      const base = new Set(basePurposeWords(line));
      const added = purposeWordsFoundForTest(line).filter(w => !base.has(w));
      expect(added, `${caseName(index)}, line ${n}: ${JSON.stringify(line)}`).toEqual([]);
      const mapped = redactSecretsForReportWithOrigins(line);
      expect(mapped.text, `origin map, ${caseName(index)}, line ${n}`).toBe(redactSecretsForReport(line));
      const purpose = declaredPurposeForTest(line).text;
      if (purpose.includes('[REDACTED_')) redacted++;
      const addedByTable = tablePurposeWords(line).filter(w => !base.has(w));
      expect(addedByTable, `through the table, ${caseName(index)}, line ${n}: ${JSON.stringify(line)}`).toEqual([]);
    }
    // The cell is about lines holding keys: most of them do, and the table
    // replaces a key on many of them.
    expect(withKey, `lines holding a key, seed ${SEED}`).toBeGreaterThan(200);
    expect(redacted, `lines the table redacts, seed ${SEED}`).toBeGreaterThan(100);
  });
});

describe('the origin map of the report redaction', () => {
  it('produces the report redaction text, with origins in order', () => {
    generatedCase(ORIGIN_CASE, () => {
      const p = drawer(caseSeed(ORIGIN_CASE));
      const pemLines = [`-----B${'EGIN'} RSA PRIVATE KEY-----`, p.run(64, `${ALNUM}+/`), p.run(64, `${ALNUM}+/`), `-----E${'ND'} RSA PRIVATE KEY-----`];
      const inputs = [
        `head\n${pemLines.join('\n')}\ntail https://h/x`,
        `aws_secret_access_key = "${p.run(40, `${ALNUM}/+`)}" then postgres://u:p@h/db`,
        `password: "${p.run(12)}" and sk-${p.run(40)} and ghp_${p.run(36)}`,
        'nothing to redact here',
      ];
      for (const input of inputs) {
        const { text, from, to } = redactSecretsForReportWithOrigins(input);
        expect(text).toBe(redactSecretsForReport(input));
        expect(from).toHaveLength(text.length);
        for (let i = 0; i < text.length; i++) {
          expect(from[i]).toBeLessThan(to[i]);
          if (i > 0) expect(from[i]).toBeGreaterThanOrEqual(from[i - 1]);
        }
      }
      // Untouched text maps to itself.
      const plain = redactSecretsForReportWithOrigins('nothing to redact here');
      expect([...plain.from]).toEqual([...Array(22).keys()]);
    });
  });
});
