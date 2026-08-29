/**
 * HMA-01.AC4 — `fix-all --scan-only` and `secure` do not return opposite
 * verdicts on one tree (#477, second carry).
 *
 * The defect: on a directory where `secure` reported a CRITICAL hardcoded
 * secret and exited 1, `fix-all --scan-only` printed
 * `Credential Protection  [+] No issues found` and exited 0 — and `secure --fix`
 * routes users to `fix-all` in its own output. Two analyzers in one tool,
 * opposite directions, same artifact.
 *
 * WHAT WAS ACTUALLY WRONG, and what the fix therefore is. It was never a
 * disagreement about which credential SHAPES count: `credvault`'s catalog
 * already carried the vendor shapes `secure` reports. It was a disagreement
 * about which FILES get opened — `credvault` read fourteen fixed config paths,
 * so an ordinary `.py` or `.ts` holding an API key was outside its population
 * entirely. It now sweeps the same source extensions `artifact-parser.ts`
 * classifies as `source_code`, with the same catalog, and reports CRED-005.
 *
 * CRED-005 IS NOT AUTO-FIXABLE, deliberately. `fix()` rewrites the config paths
 * and nothing else, so marking it fixable would print a remedy that never runs
 * and would clear the finding out of `remainingFindings`, which is the list the
 * exit code reads.
 *
 * The first block runs without a build, so the plugin-level property holds in
 * any environment. The second spawns both commands, because "the two agree" is
 * a statement about two exit codes and only the built CLI has them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { CredVaultPlugin } from '../../src/plugins/credvault';

beforeAll(assertDistFreshIfPresent);

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const ARTIFACT = join('app', 'service.py');

/**
 * A key synthesized at run time, for the reason the rest of this repo
 * synthesizes them: the detector skips any value whose own bytes carry a
 * placeholder marker, so a fixture using the house FAKE marker would be
 * vacuously green, and committing a credential-shaped literal is worse. Hex is
 * a subset of the vendor character class and cannot spell a marker.
 */
function anthropicKey(): string {
  return `sk-ant-api03-${randomBytes(40).toString('hex').slice(0, 40).toUpperCase()}`;
}

/** A tree whose only credential sits in an ordinary source file. */
function treeWithSourceSecret(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-01-ac4-'));
  mkdirSync(join(dir, 'app'), { recursive: true });
  writeFileSync(
    join(dir, ARTIFACT),
    [
      '# Billing worker.',
      'import httpx',
      '',
      `ANTHROPIC_KEY = "${anthropicKey()}"`,
      '',
      'def client():',
      '    return httpx.Client(headers={"x-api-key": ANTHROPIC_KEY})',
      '',
    ].join('\n'),
    'utf-8',
  );
  return dir;
}

interface Run {
  status: number | null;
  out: string;
}

function runCli(args: string[]): Run {
  const r = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    timeout: 120_000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
  });
  return {
    status: r.status,
    out: `${(r.stdout ?? '').replace(STRIP_ANSI, '')}\n${(r.stderr ?? '').replace(STRIP_ANSI, '')}`,
  };
}

function firstJsonObject(text: string): Record<string, unknown> {
  const start = text.indexOf('{');
  expect(start, `no JSON object in output: ${text.slice(0, 300)}`).toBeGreaterThanOrEqual(0);
  return JSON.parse(text.slice(start, text.lastIndexOf('}') + 1)) as Record<string, unknown>;
}

describe('HMA-01.AC4: the Credential Protection plugin reads source files', () => {
  it('HMA-01.AC4 credvault reports a CRITICAL for a key in an ordinary source file', async () => {
    const dir = treeWithSourceSecret();
    const plugin = new CredVaultPlugin();
    await plugin.init();
    const findings = await plugin.scan(dir);

    const onSource = findings.filter((f) => f.filePath === ARTIFACT);
    expect(
      onSource.length,
      `credvault must not report a source file holding an API key as clean. Got: ${
        findings.map((f) => `${f.id} ${f.filePath}`).join(', ') || '(none)'
      }`,
    ).toBeGreaterThan(0);
    expect(onSource.some((f) => f.severity === 'critical')).toBe(true);
    // Not auto-fixable, so it survives the fix pass and reaches the exit code.
    expect(onSource.every((f) => f.autoFixable === false)).toBe(true);
    expect(onSource.every((f) => Number.isInteger(f.line))).toBe(true);
  });

  it('HMA-01.AC4 credvault still reports nothing on a source tree with no credential', async () => {
    // The cheapest way to pass the assertion above is to report every source
    // file, so the negative half is pinned beside it.
    const dir = mkdtempSync(join(tmpdir(), 'hma-01-ac4-clean-'));
    mkdirSync(join(dir, 'app'), { recursive: true });
    writeFileSync(
      join(dir, ARTIFACT),
      ['import os', '', 'KEY = os.environ["ANTHROPIC_API_KEY"]', ''].join('\n'),
      'utf-8',
    );
    const plugin = new CredVaultPlugin();
    await plugin.init();
    expect(await plugin.scan(dir)).toEqual([]);
  });
});

describe('HMA-01.AC4: fix-all --scan-only agrees in direction with secure', () => {
  it('HMA-01.AC4 dist/cli.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('HMA-01.AC4 secure and fix-all --scan-only return the same direction on one tree', () => {
    if (!existsSync(CLI_PATH)) return;
    const dir = treeWithSourceSecret();

    const secure = runCli(['secure', dir, '--json', '--no-machine-posture']);
    const secureBody = firstJsonObject(secure.out);
    const secureFindings = (secureBody.findings ?? []) as Array<{
      severity?: string;
      category?: string;
      passed?: boolean;
    }>;

    // Non-vacuity: the comparison only means something while `secure` really
    // does report a CRITICAL credential on this tree.
    expect(
      secureFindings.some((f) => !f.passed && f.severity === 'critical'),
      'secure reported no CRITICAL — the adversarial fixture stopped reproducing',
    ).toBe(true);
    expect(secure.status, 'secure must fail the tree it calls critical').toBe(1);

    const fixAll = runCli(['fix-all', dir, '--scan-only', '--json']);
    const fixAllBody = firstJsonObject(fixAll.out);
    const plugins = (fixAllBody.plugins ?? []) as Array<{
      name: string;
      findings: Array<{ severity?: string }>;
    }>;
    const credential = plugins.find((p) => p.name === 'Credential Protection');
    expect(credential, 'fix-all must run the Credential Protection plugin').toBeDefined();

    expect(
      credential!.findings.length,
      'fix-all reported Credential Protection clean on a tree secure calls CRITICAL',
    ).toBeGreaterThan(0);
    expect(
      fixAll.status,
      `direction disagreement: secure exited ${secure.status}, fix-all --scan-only exited ${fixAll.status}`,
    ).not.toBe(0);
  });

  it('HMA-01.AC4 the text channel does not print "No issues found" for Credential Protection', () => {
    if (!existsSync(CLI_PATH)) return;
    const dir = treeWithSourceSecret();
    const run = runCli(['fix-all', dir, '--scan-only']);

    const block = run.out.split('> Credential Protection')[1] ?? '';
    expect(block, 'the Credential Protection block did not render').not.toBe('');
    expect(block.split('\n').slice(0, 4).join('\n')).not.toMatch(/No issues found/);
    expect(run.status).not.toBe(0);
  });

  it('HMA-01.AC4 --scan-only writes nothing to the tree it reports on', () => {
    if (!existsSync(CLI_PATH)) return;
    const dir = treeWithSourceSecret();
    const before = readFileSync(join(dir, ARTIFACT), 'utf-8');
    runCli(['fix-all', dir, '--scan-only']);
    const after = readFileSync(join(dir, ARTIFACT), 'utf-8');
    expect(after, 'a scan-only run must not rewrite source').toBe(before);
  });
});
