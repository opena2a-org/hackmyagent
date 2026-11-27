/**
 * A key is reported whatever its own characters spell.
 *
 * The credential analyzer reads the artifact's declared purpose for the words
 * test, example, documentation, fixture and demo, and reads a file whose
 * purpose carries one as a test, example or documentation file. With no
 * frontmatter the declared purpose is the first long line, which for
 * `const openai = "sk-…"` is the key's own line. The purpose is read with
 * every credential-shaped value removed, so a 32-character `sk-` body that
 * spells one of those words is still reported with AST-CRED-001.
 *
 * EXAMPLE is the exception, and stays one: a key containing it, in any letter
 * case, is a placeholder and produces no finding (the control in
 * openai-style-sk-key.test.ts).
 *
 * A file that is a test by its path, or by words outside the key, keeps the
 * result it had before; the last two blocks pin that result as it is.
 *
 * The keys are drawn at run time, so no credential-shaped literal sits in the
 * repository. Each run draws a new seed and prints it; HMA_TEST_SEED=<seed>
 * replays that run. Every case draws from its own stream, made from the seed
 * and the case's index, so a case draws the same keys when it runs alone, and
 * a failure names the seed and the case.
 */

import { describe, it, expect } from 'vitest';
import { createHash, randomInt } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { scanCanonicalCredentialFormatsForTest } from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PLACEHOLDER = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE/i;

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
process.stdout.write(`__tests__/nanomind-core/key-spells-purpose-word.test.ts seed: HMA_TEST_SEED=${SEED}\n`);

/** The seed of case `index`'s own stream. */
function caseSeed(index: number): number {
  return createHash('sha256').update(`${SEED}:${index}`).digest().readUInt32BE(0);
}

/** mulberry32, restarted by each case from its own seed. */
let state = 0;
function nextByte(): number {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) & 0xff;
}

/** `n` drawn alphanumerics that spell no placeholder marker. */
function filler(n: number): string {
  for (;;) {
    let s = '';
    for (let i = 0; i < n; i++) s += ALNUM[nextByte() % ALNUM.length];
    if (!PLACEHOLDER.test(s)) return s;
  }
}

/** A 32-character body with `word` inside it, at a drawn offset. */
function bodyWith(word: string): string {
  const before = nextByte() % (32 - word.length + 1);
  return `${filler(before)}${word}${filler(32 - word.length - before)}`;
}

/**
 * Runs case `index` from its own stream. A failure's message is led by the
 * seed and the case's index.
 */
async function generatedCase(index: number, run: () => Promise<void>): Promise<void> {
  state = caseSeed(index);
  try {
    await run();
  } catch (error) {
    if (error instanceof Error) error.message = `seed ${SEED}, case ${index}: ${error.message}`;
    throw error;
  }
}

let nextCase = 0;

const reported = (key: string) => `const openai = "${key}";\n`;

/** Failing finding ids and severities from the real semantic pipeline. */
async function failingFindings(file: string, content: string): Promise<string[]> {
  const dir = tempDir('hma-key-spells-');
  mkdirSync(dirname(join(dir, file)), { recursive: true });
  await writeFile(join(dir, file), content, 'utf-8');
  const result = await runNanoMindScan(dir, []);
  return result.mergedFindings
    .filter(f => !f.passed)
    .map(f => `${f.checkId}:${f.severity}`)
    .sort();
}

const SPELLINGS: Record<string, [string, string, string]> = {
  test: ['test', 'TEST', 'tEsT'],
  documentation: ['documentation', 'DOCUMENTATION', 'DocuMENTation'],
  fixture: ['fixture', 'FIXTURE', 'fIXtuRe'],
  demo: ['demo', 'DEMO', 'DeMo'],
};

describe('a key whose body spells a purpose word is reported with AST-CRED-001', () => {
  for (const [word, spellings] of Object.entries(SPELLINGS)) {
    for (const spelling of spellings) {
      const index = nextCase++;
      it(`a 32-character sk- body containing ${spelling}`, async () => {
        await generatedCase(index, async () => {
          const key = `sk-${bodyWith(spelling)}`;
          expect(key).toHaveLength(35);
          expect(key.toLowerCase()).toContain(word);
          // The shape is the same as any other 32-character key.
          expect(scanCanonicalCredentialFormatsForTest(reported(key)).map(h => h.label))
            .toEqual(['OpenAI-style sk- key']);
          expect(await failingFindings('index.js', reported(key)))
            .toEqual(['AST-CRED-001:high', 'AST-CRED-003:critical']);
        });
      }, 120_000);
    }
  }
});

describe('a key containing EXAMPLE keeps the placeholder rule', () => {
  for (const spelling of ['example', 'EXAMPLE', 'ExAmPle']) {
    const index = nextCase++;
    it(`a 32-character sk- body containing ${spelling} produces no finding`, async () => {
      await generatedCase(index, async () => {
        const content = reported(`sk-${bodyWith(spelling)}`);
        expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
        expect(await failingFindings('index.js', content)).toEqual([]);
      });
    }, 120_000);
  }
});

describe('a file that is a test by its path keeps its result', () => {
  for (const [word, spellings] of Object.entries(SPELLINGS)) {
    const index = nextCase++;
    it(`test/index.js holding a key that spells ${word}, and one that spells nothing`, async () => {
      await generatedCase(index, async () => {
        expect(await failingFindings('test/index.js', reported(`sk-${bodyWith(spellings[2])}`))).toEqual([]);
        expect(await failingFindings('test/index.js', reported(`sk-${filler(32)}`))).toEqual([]);
      });
    }, 120_000);
  }
});

describe('a file that is a test by words outside the key keeps its result', () => {
  for (const [word, spellings] of Object.entries(SPELLINGS)) {
    const index = nextCase++;
    it(`the word ${word} in the variable name, with and without it in the key`, async () => {
      await generatedCase(index, async () => {
        const carrier = (key: string) => `const ${word}_openai = "${key}";\n`;
        expect(await failingFindings('index.js', carrier(`sk-${bodyWith(spellings[1])}`)))
          .toEqual(['AST-CRED-003:critical']);
        expect(await failingFindings('index.js', carrier(`sk-${filler(32)}`)))
          .toEqual(['AST-CRED-003:critical']);
      });
    }, 120_000);
  }
});
