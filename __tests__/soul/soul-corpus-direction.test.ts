/**
 * Corpus-gated cross-analyzer direction agreement (#251).
 *
 * Runs the BUILT CLI (dist/cli.js) against the real adversarial-corpus soul
 * fixtures and asserts that secure, check, and scan-soul agree on direction:
 *
 *   soul/benign/hardened-soul       → all three pass (no HIGH-class output)
 *   soul/malicious/permissive-overrides-soul → all three flag it
 *
 * Skips when the private corpus checkout (~/.opena2a/corpus) or dist/ build
 * is absent (CI does not carry the corpus; release-smoke and local runs do).
 * Structural equivalents of these fixtures are asserted unconditionally in
 * soul-direction-agreement.test.ts.
 */

import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const execFileAsync = promisify(execFile);

const CORPUS = path.join(os.homedir(), '.opena2a', 'corpus', 'soul');
const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const BENIGN = path.join(CORPUS, 'benign', 'hardened-soul');
const MALICIOUS = path.join(CORPUS, 'malicious', 'permissive-overrides-soul');

const available =
  fs.existsSync(CLI) && fs.existsSync(BENIGN) && fs.existsSync(MALICIOUS);

const ENV = {
  ...process.env,
  OPENA2A_CORPUS_DETERMINISTIC: '1',
  NO_COLOR: '1',
};

async function cli(args: string[]): Promise<{ code: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync(process.execPath, [CLI, ...args], {
      env: ENV,
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    return { code: 0, stdout };
  } catch (err: unknown) {
    const e = err as { code?: number; stdout?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '' };
  }
}

describe.skipIf(!available)('corpus soul fixtures: cross-analyzer direction (#251)', () => {
  it('benign hardened-soul: scan-soul reports zero violations and no clamp', async () => {
    const { stdout } = await cli(['scan-soul', BENIGN, '--json']);
    const result = JSON.parse(stdout);
    expect(result.violations ?? []).toHaveLength(0);
    expect(result.scoreClamped ?? false).toBe(false);
  });

  it('malicious permissive-overrides-soul: scan-soul detects violations and clamps', async () => {
    const { stdout } = await cli(['scan-soul', MALICIOUS, '--json']);
    const result = JSON.parse(stdout);
    expect(
      (result.violations ?? []).length,
      `expected violations on the malicious corpus SOUL; got score=${result.score}`,
    ).toBeGreaterThan(0);
    expect(result.score).toBeLessThanOrEqual(25);
  });

  it('direction separation on the real corpus pair: benign > malicious', async () => {
    const benign = JSON.parse((await cli(['scan-soul', BENIGN, '--json'])).stdout);
    const malicious = JSON.parse((await cli(['scan-soul', MALICIOUS, '--json'])).stdout);
    expect(
      benign.score,
      `benign (${benign.score}) must score strictly above malicious (${malicious.score})`,
    ).toBeGreaterThan(malicious.score);
  });

  it('benign hardened-soul: check --no-registry emits no high/critical finding', async () => {
    const { stdout } = await cli(['check', BENIGN, '--no-registry', '--json']);
    const result = JSON.parse(stdout);
    // check --json reports counts in `high`/`critical` with the finding
    // array in `details`.
    const details: Array<{ severity?: string; checkId?: string }> = Array.isArray(result.details)
      ? result.details
      : [];
    expect(
      (result.high ?? 0) + (result.critical ?? 0),
      `check must not flag the benign hardened SOUL. Got: ${details
        .map(f => `${f.checkId}(${f.severity})`)
        .join('; ')}`,
    ).toBe(0);
  });

  it('benign hardened-soul: secure stays within the manifest band (>=90, exit 0)', async () => {
    const { code, stdout } = await cli(['secure', BENIGN, '--json']);
    const result = JSON.parse(stdout);
    const score = result.score ?? result.securityScore;
    expect(score).toBeGreaterThanOrEqual(90);
    expect(code).toBe(0);
  });

  it('malicious permissive-overrides-soul: secure still flags it (high/critical present)', async () => {
    const { stdout } = await cli(['secure', MALICIOUS, '--json']);
    const result = JSON.parse(stdout);
    const findings: Array<{ severity: string }> = result.findings ?? [];
    expect(
      findings.filter(f => f.severity === 'high' || f.severity === 'critical').length,
      'secure must keep flagging the malicious corpus SOUL',
    ).toBeGreaterThan(0);
  });
});
