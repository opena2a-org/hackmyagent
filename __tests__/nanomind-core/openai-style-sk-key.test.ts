/**
 * #316. `secure` scored a two-file project, `package.json` plus
 * `index.js` holding `const openai = "sk-<32 random alphanumerics>"`, 96/100
 * with exit 0. The canonical list knew `sk-` only with a 48+ character body,
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
 * the fixture would then pass for the wrong reason.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
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

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PLACEHOLDER = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE/i;

/** `n` random alphanumerics that spell no placeholder marker. */
function randomBody(n: number): string {
  for (;;) {
    let body = '';
    for (const byte of randomBytes(n)) body += ALNUM[byte % ALNUM.length];
    if (!PLACEHOLDER.test(body) && new Set(body).size > 6) return body;
  }
}

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

  it('secure --ci exits 1', () => {
    expect(secure(['--ci']).status).toBe(1);
  });

  it('gets the same check ids and severities as a 48-character legacy key', async () => {
    const legacy = await failingFindings(reported(`sk-${randomBody(48)}`));
    // Without this, two empty lists would compare equal and prove nothing.
    expect(legacy).toContain('AST-CRED-003:critical');
    expect(await failingFindings(reported(`sk-${body}`))).toEqual(legacy);
  });
});

describe('#316: controls that must produce nothing', () => {
  const sha256 = () => randomBytes(32).toString('hex');
  const controls: Array<[string, () => string]> = [
    ['task- plus 64 hex characters', () => `const id = "task-${sha256()}";\n`],
    ['disk- plus 64 hex characters', () => `primary: "disk-${sha256()}",\n`],
    ['sk- plus 32 x', () => reported(`sk-${'x'.repeat(32)}`)],
    ['a 32-character body containing EXAMPLE', () => reported(`sk-${randomBody(25)}EXAMPLE`)],
    ['process.env.OPENAI_API_KEY', () => 'const openai = process.env.OPENAI_API_KEY;\n'],
  ];
  for (const [name, make] of controls) {
    it(`${name} produces no finding`, async () => {
      const content = make();
      expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
      expect(await failingFindings(content)).toEqual([]);
    }, 120_000);
  }
});

describe('#316: the 32-47 band hands off to the legacy shape at 48', () => {
  it('31 characters is below the band', () => {
    expect(labels(reported(`sk-${randomBody(31)}`))).toEqual([]);
  });

  it('every body from 32 to 47 characters is reported once, under the new label', () => {
    for (let n = 32; n <= 47; n++) {
      expect(labels(reported(`sk-${randomBody(n)}`)), `${n} characters`).toEqual(['OpenAI-style sk- key']);
    }
  });

  it('every body from 48 characters up is reported once, under the legacy label', () => {
    for (const n of [48, 49, 64, 120]) {
      expect(labels(reported(`sk-${randomBody(n)}`)), `${n} characters`).toEqual(['OpenAI legacy key']);
    }
  });

  it('a body of six distinct characters is a mask, a body of seven is not', () => {
    expect(labels(reported(`sk-${'abc123'.repeat(6).slice(0, 32)}`))).toEqual([]);
    expect(labels(reported(`sk-${'abc1234'.repeat(5).slice(0, 32)}`))).toEqual(['OpenAI-style sk- key']);
  });

  it('the prefixed siblings keep their own labels', () => {
    expect(labels(reported(`sk-proj-${randomBody(32)}`))).toEqual(['OpenAI project key']);
    expect(labels(reported(`sk-ant-api03-${randomBody(32)}`))).toEqual(['Anthropic API key']);
  });

  it('the keyword-context path reads the new entry through its own loop', () => {
    expect(analyzeCredentialKeywordContext(`{"token": null}\n${reported(`sk-${randomBody(32)}`)}`))
      .toBe('value-present');
    expect(analyzeCredentialKeywordContext(`{"token": null}\n${reported(`sk-${'x'.repeat(32)}`)}`))
      .toBe('schema-only');
  });
});

describe('#316: scan time is linear on 1 MB of sk- and alphanumerics', () => {
  // The cap is the largest input the scan reads, so it is the input to time.
  const size = maxCredentialScanBytesForTest();
  const fill = (unit: string, n: number) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
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
  ];

  function timeScan(content: string): number {
    const started = performance.now();
    scanCanonicalCredentialFormatsForTest(content);
    analyzeCredentialKeywordContext(content);
    return performance.now() - started;
  }

  it('each hostile shape scans 1 MB in under two seconds, and a quarter of it in proportion', () => {
    const full = hostile(size);
    const quarter = hostile(size / 4);
    for (let i = 0; i < full.length; i++) {
      expect(full[i].length).toBe(size);
      timeScan(quarter[i]); // warm the regex before timing it
      const small = timeScan(quarter[i]);
      const large = timeScan(full[i]);
      expect(large, `shape ${i}: 1 MB took ${Math.round(large)} ms`).toBeLessThan(2000);
      // Linear is about 4x for 4x the input; quadratic is about 16x. The floor
      // keeps sub-millisecond timer noise from deciding the ratio.
      expect(large, `shape ${i}: ${Math.round(small)} ms -> ${Math.round(large)} ms`)
        .toBeLessThan(Math.max(small, 5) * 10);
    }
  });
});
