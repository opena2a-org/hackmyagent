/**
 * Deep analysis keeps its cache in the tool's state directory and redacts what
 * it stores.
 *
 * The Layer 3 cache holds the analyst's findings for each file it sent, and a
 * finding can quote the line it is about, credential value included. Written
 * to `.hackmyagent-cache/` in the working directory, which is usually the
 * scanned repository, that copy was one broad `git add` away from a commit.
 *
 * Each run here spawns the built CLI with the scanned tree as its working
 * directory, the way a user runs it. Nothing leaves the machine:
 * loopback-only.cjs refuses every connection to a host that is not loopback,
 * and provider-stub.cjs answers the provider's API locally with a finding that
 * quotes a credential-keyed canary built at run time.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { projectKey } from '../../src/store/project-store';

const LOOPBACK_ONLY = path.resolve(__dirname, '..', 'helpers', 'loopback-only.cjs');
const PROVIDER_STUB = path.resolve(__dirname, '..', 'helpers', 'provider-stub.cjs');
const SPAWN_TIMEOUT = 170_000;
const CACHE_ENTRY = /^[0-9a-f]{64}\.json$/;

const canary = `canary-${randomUUID()}`;
const instructions = [
  '# Agent',
  '',
  'The agent answers questions about the release process.',
  '',
  `deploy_password: ${canary}`,
  '',
].join('\n');

/** What the stub's analyst reports: a finding that quotes the line it is about. */
const reportedFindings = [{
  line: 5,
  type: 'Hardcoded credential',
  severity: 'high',
  description: `CLAUDE.md line 5 holds deploy_password: ${canary}`,
  rationale: `deploy_password: ${canary} is a plaintext credential in an instruction file`,
  recommendation: 'Move the value to an environment variable.',
}];

let base: string;
let home: string;
let providerLog: string;

function makeTree(name: string): string {
  const dir = path.join(base, name);
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'CLAUDE.md'), instructions);
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  return dir;
}

function deepScan(dir: string): { status: number | null; stderr: string } {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY;
  const r = spawnSync(process.execPath, [BUILT_CLI, 'secure', dir, '--deep'], {
    cwd: dir,
    encoding: 'utf8',
    timeout: SPAWN_TIMEOUT,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: path.join(home, '.opena2a'),
      // Placeholder: every request it would authorise is answered by the stub.
      ANTHROPIC_API_KEY: 'placeholder-not-a-key',
      NODE_OPTIONS: `--require "${LOOPBACK_ONLY}" --require "${PROVIDER_STUB}"`,
      HMA_TEST_PROVIDER_LOG: providerLog,
      HMA_TEST_PROVIDER_FINDINGS: JSON.stringify(reportedFindings),
    },
  });
  if (r.error) throw r.error;
  return { status: r.status, stderr: String(r.stderr ?? '') };
}

/** Every file under `dir`, as absolute paths. */
function filesUnder(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.join(e.parentPath, e.name));
}

/** The Layer 3 requests the stub answered: those that offered `report_findings`. */
function layer3Requests(): number {
  if (!fs.existsSync(providerLog)) return 0;
  return fs.readFileSync(providerLog, 'utf8').trim().split('\n').filter(Boolean)
    .map((line) => JSON.parse(JSON.parse(line).body) as { tools?: Array<{ name: string }> })
    .filter((req) => (req.tools ?? []).some((t) => t.name === 'report_findings'))
    .length;
}

function stateCacheDir(tree: string): string {
  const key = projectKey(fs.realpathSync.native(tree));
  return path.join(home, '.opena2a', 'projects', key, 'llm-cache');
}

let first: string;
let second: string;
let firstRequests: number;
let secondRequests: number;

beforeAll(() => {
  assertDistFresh();
  base = tempDir('hma-deep-cache-');
  home = path.join(base, 'home');
  fs.mkdirSync(home);
  providerLog = path.join(base, 'provider.jsonl');

  first = makeTree('first');
  const a = deepScan(first);
  firstRequests = layer3Requests();
  if (firstRequests === 0) {
    throw new Error(`the first deep scan made no Layer 3 request, so this file measured nothing (exit ${a.status}): ${a.stderr.slice(0, 2000)}`);
  }

  // The same file content in a second tree.
  second = makeTree('second');
  deepScan(second);
  secondRequests = layer3Requests() - firstRequests;
}, 2 * SPAWN_TIMEOUT + 30_000);

describe('the Layer 3 cache lives in the state directory, keyed by the scanned tree', () => {
  it('writes no cache file inside the scanned tree, which was also the working directory', () => {
    for (const tree of [first, second]) {
      const inTree = filesUnder(tree).filter((f) => f.includes('.hackmyagent-cache') || CACHE_ENTRY.test(path.basename(f)));
      expect(inTree, `cache files written inside ${tree}`).toEqual([]);
    }
  });

  it('writes the cache entry under the state directory of the scanned tree', () => {
    const entries = filesUnder(stateCacheDir(first)).filter((f) => CACHE_ENTRY.test(path.basename(f)));
    expect(entries.length, `no cache entry under ${stateCacheDir(first)}`).toBeGreaterThan(0);
  });

  it('does not share entries between two trees, even for identical file content', () => {
    expect(stateCacheDir(second)).not.toBe(stateCacheDir(first));
    expect(
      secondRequests,
      'the second tree was answered from the first tree\'s cache entry instead of being analysed',
    ).toBeGreaterThan(0);
    const entries = filesUnder(stateCacheDir(second)).filter((f) => CACHE_ENTRY.test(path.basename(f)));
    expect(entries.length).toBeGreaterThan(0);
  });
});

describe('a stored finding passes through the credential redaction', () => {
  it('no cache entry, in the tree or in the state directory, holds the canary its finding quoted', () => {
    const entries = [first, second, home]
      .flatMap(filesUnder)
      .filter((f) => CACHE_ENTRY.test(path.basename(f)));
    expect(entries.length, 'no cache entry was written, so there is nothing to check').toBeGreaterThan(0);

    const holding = entries.filter((f) => fs.readFileSync(f, 'utf8').includes(canary));
    expect(holding.map((f) => path.relative(base, f)), 'cache entries holding the credential value').toEqual([]);

    // The finding itself was kept: only the value was replaced.
    const stored = JSON.parse(fs.readFileSync(entries[0], 'utf8')) as { findings: Array<{ description: string }> };
    expect(stored.findings).toHaveLength(1);
    expect(stored.findings[0].description).toContain('deploy_password: [REDACTED]');
  });
});
