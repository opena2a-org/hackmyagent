/**
 * The report redaction covers every key length the detector reports, and the
 * purpose test reads no key's or placeholder's characters.
 *
 * With no frontmatter an artifact's declared purpose is its first long line,
 * taken from the content after `redactSecretsForReportReporting` has run over
 * it. The credential analyzer reads that purpose for test, example,
 * documentation, fixture and demo. The redaction table's `openai-key` rule
 * floors at 32, the lowest body the detector reports for `sk-`, so a key in
 * the 32 to 47 band is removed where the purpose is produced, like a longer
 * one. And the purpose test removes every credential-shaped value before it
 * reads, a placeholder containing EXAMPLE included: whether a value is a
 * placeholder is judged on the value, and a placeholder on line 1 says nothing
 * about a real key on line 3.
 *
 * Every key is drawn at run time from a fixed seed: no credential-shaped
 * literal sits in the repository, and a failing draw is the same on every run.
 */

import { describe, it, expect } from 'vitest';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  SemanticCompiler,
  scanCanonicalCredentialFormatsForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
/** Words a draw must not spell: the placeholder markers and the purpose words. */
const UNWANTED =
  /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|SAMPLE|XXX|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE|TEST|DOCUMENTATION|FIXTURE|DEMO/i;

/** mulberry32 from a fixed seed. */
let state = 0x1993;
function nextByte(): number {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) & 0xff;
}

/** `n` drawn characters of `alphabet` that spell no unwanted word. */
function filler(n: number, alphabet = ALNUM): string {
  for (;;) {
    let s = '';
    for (let i = 0; i < n; i++) s += alphabet[nextByte() % alphabet.length];
    if (!UNWANTED.test(s)) return s;
  }
}

/** A body of `length` characters with `word` inside it at a drawn offset. */
function bodyWith(word: string, length: number, alphabet = ALNUM): string {
  const before = nextByte() % (length - word.length + 1);
  return `${filler(before, alphabet)}${word}${filler(length - word.length - before, alphabet)}`;
}

const SPELLINGS = ['demo', 'tEsT', 'DOCUMENTATION', 'fixture'] as const;
const LENGTHS = [32, 40, 47] as const;

/** A plain variable name on the file's first line, in each language. */
const CARRIERS: Array<{ file: string; line: (value: string) => string }> = [
  { file: 'index.ts', line: v => `const value = "${v}";\n` },
  { file: 'app.py', line: v => `value = "${v}"\n` },
];

/** Failing finding ids from the real semantic pipeline, sorted. */
async function failingIds(file: string, content: string): Promise<string[]> {
  const dir = tempDir('hma-redaction-lengths-');
  await writeFile(join(dir, file), content, 'utf-8');
  const result = await runNanoMindScan(dir, []);
  return [...new Set(result.mergedFindings.filter(f => !f.passed).map(f => f.checkId))].sort();
}

const BOTH = ['AST-CRED-001', 'AST-CRED-003'];

describe('F1: an sk- key of 32 to 47 characters spelling a purpose word is reported', () => {
  for (const length of LENGTHS) {
    for (const spelling of SPELLINGS) {
      for (const { file, line } of CARRIERS) {
        it(`a ${length}-character body containing ${spelling}, in ${file}`, async () => {
          const body = bodyWith(spelling, length);
          const content = line(`sk-${body}`);
          expect(scanCanonicalCredentialFormatsForTest(content)).toHaveLength(1);
          expect(await failingIds(file, content)).toEqual(BOTH);
        }, 120_000);
      }
    }
  }
});

/** base64url of a JSON object: the encoding of a JWT's first two segments. */
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');

/**
 * One row per detector shape whose body can spell a word. The vendor shapes
 * sit under a plain variable name. A JWT and a high-entropy run are reported
 * only beside a credential noun, so they sit under a quoted `"apiKey"` key,
 * which the report redaction's name rule does not read: their value stays on
 * the purpose line, and the purpose test removes it there.
 */
const SHAPE_ROWS: Array<{ shape: string; value: () => string; line: (v: string) => string; ids: string[] }> = [
  { shape: 'OpenAI-style sk- key (32-47)', value: () => `sk-${bodyWith('demo', 40)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'OpenAI legacy key (48+)', value: () => `sk-${bodyWith('fixture', 56)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'OpenAI project key', value: () => `sk-proj-${bodyWith('tEsT', 40)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'Anthropic API key', value: () => `sk-ant-api03-${bodyWith('DOCUMENTATION', 40)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'AWS access key', value: () => `AKIA${bodyWith('DEMO', 16, UPPER_ALNUM)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'GitHub personal access token', value: () => `ghp_${bodyWith('demo', 36)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'GitHub OAuth token', value: () => `gho_${bodyWith('fixture', 36)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'GitHub app token', value: () => `ghs_${bodyWith('tEsT', 36)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'Slack bot token', value: () => `xoxb-${bodyWith('demo', 24)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'Google API key', value: () => `AIza${bodyWith('fixture', 35)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'Stripe live key', value: () => `sk_live_${bodyWith('DOCUMENTATION', 30)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'Hugging Face token', value: () => `hf_${bodyWith('demo', 36)}`, line: CARRIERS[0].line, ids: BOTH },
  { shape: 'GitLab personal access token', value: () => `glpat-${bodyWith('tEsT', 24)}`, line: CARRIERS[0].line, ids: BOTH },
  {
    shape: 'JSON Web Token',
    value: () => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: filler(12), iat: 1_700_000_000 })}.${bodyWith('tEsT', 43)}`,
    line: v => `const config = { "apiKey": "${v}" };\n`,
    ids: ['AST-CRED-003'],
  },
  {
    shape: 'High-entropy secret',
    value: () => bodyWith('fixture', 48),
    line: v => `const config = { "apiKey": "${v}" };\n`,
    ids: ['AST-CRED-003'],
  },
];

describe('F2: every detector shape whose body can spell a word is reported', () => {
  for (const { shape, value, line, ids } of SHAPE_ROWS) {
    it(shape, async () => {
      const key = value();
      expect(await failingIds('index.ts', line(key))).toEqual(ids);
    }, 120_000);
  }
});

describe('F3: a placeholder on line 1 does not hide a real key on line 3', () => {
  // Line 2 is neutral and long enough that the real key sits more than 120
  // characters after the placeholder, outside any window read around it.
  const middle =
    'const region = process.env.DEPLOY_REGION ?? "eu-central-1"; // read once at start-up by the uploader process\n';
  const placeholders: Array<[string, () => string]> = [
    ['an sk- placeholder containing EXAMPLE', () => `sk-${bodyWith('EXAMPLE', 40)}`],
    ['a high-entropy placeholder containing EXAMPLE', () => bodyWith('EXAMPLE', 48)],
  ];
  for (const [name, placeholder] of placeholders) {
    it(`${name}, then a real sk- key`, async () => {
      const first = `const placeholder = "${placeholder()}";\n`;
      const real = `sk-${filler(40)}`;
      const content = `${first}${middle}const value = "${real}";\n`;
      expect(content.indexOf(real) - first.length).toBeGreaterThan(120);
      expect(content.split('\n')[2]).toContain(real);
      // The real key is the one the detector reports; the placeholder alone
      // keeps its rule and produces no finding.
      expect(scanCanonicalCredentialFormatsForTest(content).map(h => h.label)).toEqual(['OpenAI-style sk- key']);
      expect(await failingIds('index.ts', `${first}${middle}`)).toEqual([]);
      expect(await failingIds('index.ts', content)).toEqual(BOTH);
    }, 120_000);
  }
});

describe('F4: the declared purpose holds none of the key and records the redaction', () => {
  const compiler = new SemanticCompiler({ useNanoMind: false });
  for (const length of LENGTHS) {
    for (const spelling of SPELLINGS) {
      for (const { file, line } of CARRIERS) {
        it(`a ${length}-character body containing ${spelling}, in ${file}`, async () => {
          const body = bodyWith(spelling, length);
          const { ast } = await compiler.compile(line(`sk-${body}`), file);
          // No run of the body of six or more characters survives in the
          // purpose, the purpose word among them.
          for (let i = 0; i + 6 <= body.length; i++) {
            expect(ast.declaredPurpose, `run at ${i}`).not.toContain(body.slice(i, i + 6));
          }
          expect(ast.declaredPurpose.toLowerCase()).not.toContain(spelling.toLowerCase());
          expect(ast.declaredPurpose).toContain('[REDACTED_OPENAI_KEY]');
          expect(ast.declaredPurposeRedaction?.status).toBe('applied');
          expect(ast.declaredPurposeRedaction?.shapes).toContain('openai-key');
        });
      }
    }
  }
});

describe('F5: controls that keep their result', () => {
  it('a 48-character body spelling a purpose word reports both findings', async () => {
    for (const { file, line } of CARRIERS) {
      expect(await failingIds(file, line(`sk-${bodyWith('demo', 48)}`))).toEqual(BOTH);
    }
  }, 120_000);

  it('a key on line 3 after a clean long line reports both findings', async () => {
    const content =
      'const region = process.env.DEPLOY_REGION ?? "eu-central-1";\n' +
      'const retries = 3;\n' +
      `const value = "sk-${bodyWith('tEsT', 40)}";\n`;
    expect(await failingIds('index.ts', content)).toEqual(BOTH);
  }, 120_000);

  it('a key under the name apiKey reports both findings', async () => {
    expect(await failingIds('index.ts', `const apiKey = "sk-${bodyWith('fixture', 40)}";\n`)).toEqual(BOTH);
  }, 120_000);
});
