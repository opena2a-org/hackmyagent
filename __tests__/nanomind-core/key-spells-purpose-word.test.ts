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
 * The keys are drawn at run time from a fixed seed, so no credential-shaped
 * literal sits in the repository and a failing key is the same on every run.
 */

import { describe, it, expect } from 'vitest';
import { mkdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { scanCanonicalCredentialFormatsForTest } from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PLACEHOLDER = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE/i;

/** mulberry32 from a fixed seed: the same keys on every run. */
let state = 0x1976;
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
      it(`a 32-character sk- body containing ${spelling}`, async () => {
        const key = `sk-${bodyWith(spelling)}`;
        expect(key).toHaveLength(35);
        expect(key.toLowerCase()).toContain(word);
        // The shape is the same as any other 32-character key.
        expect(scanCanonicalCredentialFormatsForTest(reported(key)).map(h => h.label))
          .toEqual(['OpenAI-style sk- key']);
        expect(await failingFindings('index.js', reported(key)))
          .toEqual(['AST-CRED-001:high', 'AST-CRED-003:critical']);
      }, 120_000);
    }
  }
});

describe('a key containing EXAMPLE keeps the placeholder rule', () => {
  for (const spelling of ['example', 'EXAMPLE', 'ExAmPle']) {
    it(`a 32-character sk- body containing ${spelling} produces no finding`, async () => {
      const content = reported(`sk-${bodyWith(spelling)}`);
      expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
      expect(await failingFindings('index.js', content)).toEqual([]);
    }, 120_000);
  }
});

describe('a file that is a test by its path keeps its result', () => {
  for (const [word, spellings] of Object.entries(SPELLINGS)) {
    it(`test/index.js holding a key that spells ${word}, and one that spells nothing`, async () => {
      expect(await failingFindings('test/index.js', reported(`sk-${bodyWith(spellings[2])}`))).toEqual([]);
      expect(await failingFindings('test/index.js', reported(`sk-${filler(32)}`))).toEqual([]);
    }, 120_000);
  }
});

describe('a file that is a test by words outside the key keeps its result', () => {
  for (const [word, spellings] of Object.entries(SPELLINGS)) {
    it(`the word ${word} in the variable name, with and without it in the key`, async () => {
      const carrier = (key: string) => `const ${word}_openai = "${key}";\n`;
      expect(await failingFindings('index.js', carrier(`sk-${bodyWith(spellings[1])}`)))
        .toEqual(['AST-CRED-003:critical']);
      expect(await failingFindings('index.js', carrier(`sk-${filler(32)}`)))
        .toEqual(['AST-CRED-003:critical']);
    }, 120_000);
  }
});
