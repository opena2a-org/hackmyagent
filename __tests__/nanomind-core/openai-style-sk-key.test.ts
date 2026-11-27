/**
 * #316. `secure` scored a two-file project, `package.json` plus
 * `index.js` holding `const openai = "sk-<32 random alphanumerics>"`, 96/100
 * on 0.25.1 (93/100 on the commit before this fix), with exit 0 on both. The
 * canonical list knew `sk-` only with a 48+ character body,
 * so a 32-47 character body reached no finding, while opena2a-cli's own
 * scanner flagged the same file critical.
 *
 * The fix adds one canonical entry for that band, under its own label and the
 * same check id and severity as the legacy shape. The rows below pin the
 * reported case end to end, the controls that must stay silent, the hand-off
 * at 48 characters, and linear scan time on 1 MB of hostile input.
 *
 * WHY THE KEYS ARE GENERATED AT RUN TIME: a credential-shaped literal in a
 * public repo is worse than a test that draws its own. A draw that spells a
 * placeholder marker is redrawn, because the detector correctly skips it and
 * the fixture would then pass for the wrong reason. *
 * Each run draws a new seed and prints it; HMA_TEST_SEED=<seed> replays that
 * run. Every case draws from its own stream, made from the seed and the
 * case's index, so a case draws the same keys when it runs alone, and a
 * failure names the seed and the case.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash, randomInt } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  scanCanonicalCredentialFormatsForTest,
  analyzeCredentialKeywordContext,
  maxCredentialScanBytesForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { cpuTimeMs } from '../helpers/scaling-time';

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
process.stdout.write(`__tests__/nanomind-core/openai-style-sk-key.test.ts seed: HMA_TEST_SEED=${SEED}\n`);

/** The seed of case `index`'s own stream. */
function caseSeed(index: number): number {
  return createHash('sha256').update(`${SEED}:${index}`).digest().readUInt32BE(0);
}

/**
 * The draws come from mulberry32, restarted by each case from its own seed;
 * the space drawn from is every alphanumeric body.
 */
let state = 0;
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    out[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
  }
  return out;
}

/** `n` random alphanumerics that spell no placeholder marker. */
function randomBody(n: number): string {
  for (;;) {
    let body = '';
    for (const byte of randomBytes(n)) body += ALNUM[byte % ALNUM.length];
    if (!PLACEHOLDER.test(body) && new Set(body).size > 6) return body;
  }
}

/**
 * Runs case `index` from its own stream. A failure's message is led by the
 * seed and the case's index.
 */
function generatedCase<T>(index: number, run: () => T): T {
  state = caseSeed(index);
  const named = (error: unknown): unknown => {
    if (error instanceof Error) error.message = `seed ${SEED}, case ${index}: ${error.message}`;
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

let nextCase = 0;

/** The reported carrier, byte for byte apart from the key. */
const reported = (key: string) => `const openai = "${key}";\n`;

const labels = (content: string) => scanCanonicalCredentialFormatsForTest(content).map(h => h.label);

/** Failing finding ids and severities from the real semantic pipeline. */
async function failingFindings(content: string): Promise<string[]> {
  const dir = tempDir('hma-316-');
  await writeFile(join(dir, 'index.js'), content, 'utf-8');
  const result = await runNanoMindScan(dir, []);
  return result.mergedFindings
    .filter(f => !f.passed)
    .map(f => `${f.checkId}:${f.severity}`)
    .sort();
}

describe('#316: secure reports a hardcoded sk- key with a 32-character body', { timeout: 300_000 }, () => {
  // The project's key is case 0; the tests that scan it name that case.
  const bodyCase = nextCase++;
  state = caseSeed(bodyCase);
  const body = randomBody(32);
  let project: string;
  let home: string;

  beforeAll(() => {
    assertDistFresh();
    const root = tempDir('hma-316-cli-');
    project = join(root, 'project');
    home = join(root, 'home');
    mkdirSync(project);
    mkdirSync(home);
    writeFileSync(join(project, 'package.json'), '{"name":"e","version":"1.0.0"}\n');
    writeFileSync(join(project, 'index.js'), reported(`sk-${body}`));
  });

  function secure(args: string[]) {
    return spawnSync(process.execPath, [CLI, 'secure', project, '--no-machine-posture', ...args], {
      encoding: 'utf8',
      timeout: 240_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
    });
  }

  it('secure --json reports the hardcoded secret at index.js:1, without quoting it', () => {
    generatedCase(bodyCase, () => {
      const out = secure(['--json']).stdout ?? '';
      const report = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
      const hardcoded = report.findings.filter(
        (f: { checkId: string; passed: boolean }) => !f.passed && f.checkId === 'AST-CRED-003',
      );
      expect(hardcoded).toHaveLength(1);
      expect(hardcoded[0]).toMatchObject({
        name: 'Hardcoded Secret Detected',
        severity: 'critical',
        file: 'index.js',
        line: 1,
      });
      expect(hardcoded[0].message).toContain('OpenAI-style sk- key');
      expect(out).not.toContain(body);
    });
  });

  it('secure --ci exits 1', () => {
    generatedCase(bodyCase, () => {
      expect(secure(['--ci']).status).toBe(1);
    });
  });

  const index = nextCase++;
  it('gets the same check ids and severities as a 48-character legacy key', async () => {
    await generatedCase(index, async () => {
      const legacy = await failingFindings(reported(`sk-${randomBody(48)}`));
      // Without this, two empty lists would compare equal and prove nothing.
      expect(legacy).toContain('AST-CRED-003:critical');
      expect(await failingFindings(reported(`sk-${body}`))).toEqual(legacy);
    });
  });
});

describe('#316: controls that must produce nothing', () => {
  const sha256 = () => Buffer.from(randomBytes(32)).toString('hex');
  const controls: Array<[string, () => string]> = [
    ['task- plus 64 hex characters', () => `const id = "task-${sha256()}";\n`],
    ['disk- plus 64 hex characters', () => `primary: "disk-${sha256()}",\n`],
    ['sk- plus 32 x', () => reported(`sk-${'x'.repeat(32)}`)],
    ['a 32-character body containing EXAMPLE', () => reported(`sk-${randomBody(25)}EXAMPLE`)],
    ['process.env.OPENAI_API_KEY', () => 'const openai = process.env.OPENAI_API_KEY;\n'],
  ];
  for (const [name, make] of controls) {
    const index = nextCase++;
    it(`${name} produces no finding`, async () => {
      await generatedCase(index, async () => {
        const content = make();
        expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
        expect(await failingFindings(content)).toEqual([]);
      });
    }, 120_000);
  }
});

describe('#316: the 32-47 band hands off to the legacy shape at 48', () => {
  const index31 = nextCase++;
  it('31 characters is below the band', () => {
    generatedCase(index31, () => {
      expect(labels(reported(`sk-${randomBody(31)}`))).toEqual([]);
    });
  });

  const indexBand = nextCase++;
  it('every body from 32 to 47 characters is reported once, under the new label', () => {
    generatedCase(indexBand, () => {
      for (let n = 32; n <= 47; n++) {
        expect(labels(reported(`sk-${randomBody(n)}`)), `${n} characters`).toEqual(['OpenAI-style sk- key']);
      }
    });
  });

  const indexLegacy = nextCase++;
  it('every body from 48 characters up is reported once, under the legacy label', () => {
    generatedCase(indexLegacy, () => {
      for (const n of [48, 49, 64, 120]) {
        expect(labels(reported(`sk-${randomBody(n)}`)), `${n} characters`).toEqual(['OpenAI legacy key']);
      }
    });
  });

  it('a body of six distinct characters is a mask, a body of seven is not', () => {
    expect(labels(reported(`sk-${'abc123'.repeat(6).slice(0, 32)}`))).toEqual([]);
    expect(labels(reported(`sk-${'abc1234'.repeat(5).slice(0, 32)}`))).toEqual(['OpenAI-style sk- key']);
  });

  const indexSiblings = nextCase++;
  it('the prefixed siblings keep their own labels', () => {
    generatedCase(indexSiblings, () => {
      expect(labels(reported(`sk-proj-${randomBody(32)}`))).toEqual(['OpenAI project key']);
      expect(labels(reported(`sk-ant-api03-${randomBody(32)}`))).toEqual(['Anthropic API key']);
    });
  });

  const indexKeyword = nextCase++;
  it('the keyword-context path reads the new entry through its own loop', () => {
    generatedCase(indexKeyword, () => {
      expect(analyzeCredentialKeywordContext(`{"token": null}\n${reported(`sk-${randomBody(32)}`)}`))
        .toBe('value-present');
      expect(analyzeCredentialKeywordContext(`{"token": null}\n${reported(`sk-${'x'.repeat(32)}`)}`))
        .toBe('schema-only');
    });
  });
});

describe('#316: scan time is linear on 1 MB of sk-, alphanumerics and PEM headers', () => {
  // The cap is the largest input the scan reads, so it is the input to time.
  const size = maxCredentialScanBytesForTest();
  const fill = (unit: string, n: number) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
  // Assembled from parts so this file holds no complete armor line.
  const pemBegin = '-----B' + 'EGIN RSA PRIVATE KEY-----';
  const pemEnd = '-----E' + 'ND RSA PRIVATE KEY-----';
  const hostile = (n: number) => [
    // One unbroken run: the legacy shape consumes it in one match.
    `sk-${fill(ALNUM, n - 3)}`,
    // 48-character bodies back to back: every start reaches 47, fails the
    // lookahead, and backs off to 32 before the legacy shape takes it.
    fill(`-sk-${fill(ALNUM, 48)}`, n),
    // In-band bodies back to back: every one is a hit.
    fill(`-sk-${fill(ALNUM, 40)}`, n),
    // Bare prefixes: every start fails on its second body character.
    fill('sk-', n),
    // The PEM private-key shape reads the whole text once for its placeholder
    // rule, whatever the number of headers. Headers back to back: every one
    // is a hit.
    fill(pemBegin, n),
    // A header per 4 KB of text with no alphabet character and no END.
    fill(`${pemBegin}${'.'.repeat(4000)}`, n),
    // A header per 4 KB of dashes: every dash opens a candidate header and a
    // candidate END marker, and none finishes either.
    fill(`${pemBegin}${'-'.repeat(4000)}`, n),
    // Header text one dash short, back to back: every candidate header reads
    // to its last character before it fails.
    fill(pemBegin.slice(0, -1), n),
    // Placeholder blocks that each close: every header is read and dropped.
    fill(`${pemBegin}\n<your private key here>\n${pemEnd}\n`, n),
    // Escaped line breaks between body runs, as in a JSON string: none ends
    // a run, and every block keeps its header.
    fill(`${pemBegin}\\n${pemEnd}\\n${fill(ALNUM, 20)}\\r\\n${fill(ALNUM, 20)}\\n`, n),
  ];

  /**
   * CPU time of the scan, so time the thread spends waiting for a core on a
   * loaded machine is not charged to the scan (__tests__/helpers/scaling-time.ts).
   */
  function timeScan(content: string): number {
    const started = cpuTimeMs();
    scanCanonicalCredentialFormatsForTest(content);
    analyzeCredentialKeywordContext(content);
    return cpuTimeMs() - started;
  }

  /**
   * Median of three timings of each input, taken alternately. One run on a
   * shared runner can stall for several times its length (#958: a 1 MB scan
   * that takes about 4x the quarter took 12x once), so a single sample lets
   * the scheduler decide the ratio. Alternating puts a slow stretch on both
   * sizes, and the median drops a lone stall.
   */
  function medianTimes(time: (content: string) => number, small: string, large: string) {
    const smalls: number[] = [];
    const larges: number[] = [];
    for (let run = 0; run < 3; run++) {
      smalls.push(time(small));
      larges.push(time(large));
    }
    const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1];
    return { small: median(smalls), large: median(larges) };
  }

  // Linear is about 4x for 4x the input; quadratic is about 16x. The floor
  // keeps sub-millisecond timer noise from deciding the ratio.
  const linearBound = (small: number) => Math.max(small, 5) * 10;

  /** Replays recorded timings in order, keyed by input. */
  const replay = (timings: Record<string, number[]>) => (content: string) => {
    const next = timings[content].shift();
    if (next === undefined) throw new Error(`no timing left for ${content}`);
    return next;
  };

  it('one stalled 1 MB run does not decide the ratio', () => {
    // The #958 run: the quarter took 8 ms, one 1 MB run took 97 ms.
    const { small, large } = medianTimes(
      replay({ quarter: [8.3, 8.4, 8.2], full: [97.1, 33.5, 34.0] }), 'quarter', 'full',
    );
    expect(large).toBe(34.0);
    expect(large).toBeLessThan(linearBound(small));
  });

  it('a quadratic scan still exceeds the bound on the median', () => {
    const { small, large } = medianTimes(
      replay({ quarter: [8.3, 8.4, 8.2], full: [133.0, 31.0, 134.0] }), 'quarter', 'full',
    );
    expect(large).toBeGreaterThanOrEqual(linearBound(small));
  });

  it('each hostile shape scans 1 MB in under two seconds, and a quarter of it in proportion', () => {
    const full = hostile(size);
    const quarter = hostile(size / 4);
    for (let i = 0; i < full.length; i++) {
      expect(full[i].length).toBe(size);
      timeScan(quarter[i]); // warm the regex before timing it
      const { small, large } = medianTimes(timeScan, quarter[i], full[i]);
      expect(large, `shape ${i}: 1 MB took ${Math.round(large)} ms of CPU time`).toBeLessThan(2000);
      expect(large, `shape ${i}: ${Math.round(small)} ms -> ${Math.round(large)} ms`)
        .toBeLessThan(linearBound(small));
    }
  });
});
