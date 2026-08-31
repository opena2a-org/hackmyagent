/**
 * HMA-08.AC3 – HMA-08.AC6 — `mark-stub`, the write-back half of the
 * observation -> shipped-check loop.
 *
 * DEFECT 2 of `todo/roadmap/hackmyagent-pull-stubs-status-vocabulary-mismatch.md`:
 * nothing in HMA marked a stub integrated, so the transition was manual and
 * unaudited and nobody could answer "how many confirmed observations became a
 * shipped check". [CHIEF-CPO] 2026-08-31 ruled the UX; [CHIEF-CA] 2026-08-31
 * ruled that `integrated` is REFUSED without evidence probed from the BUILT
 * artifact.
 *
 * The refusals are what is under test here, because they are what makes the
 * resulting number mean anything. `UNREACHABLE_PREFIXES` is the precedent:
 * `CODEINJ`, `TMPPATH` and `ENVLEAK` are implemented, emit findings, are
 * counted in the advertised suite and have no caller in `scanInner`. A stub
 * mapped to one of them, marked integrated, would record a shipped check
 * whose detector can never fire — worse than having no check, because the
 * ledger now says it is covered.
 *
 * The fixture for that case is therefore DERIVED, by importing
 * `UNREACHABLE_PREFIXES` from `dist/` — the same built module the probe reads.
 * A hardcoded `'CODEINJ-001'` would keep passing on the day CODEINJ is wired
 * in, asserting a refusal the product should no longer make.
 *
 * The registry leg ships separately as REG-10, so every request here goes to
 * the in-process mock and nothing needs a live registry.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import {
  startMockRegistry,
  closedPortUrl,
  stubRow,
  type MockRegistry,
  type RecordedRequest,
} from '../helpers/hma08-stub-registry';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const canRun = () => existsSync(CLI);
const VERSION = JSON.parse(
  readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'),
).version as string;

const STUB_ID = 'stub-0001';
const RECORDED_CHECK_ID = 'CRED-001';
const COMMIT = 'a1b2c3d';

let registry: MockRegistry | undefined;
afterEach(async () => { await registry?.close(); registry = undefined; });

/**
 * Spawn the built CLI WITHOUT blocking this process's event loop — the mock
 * registry runs in-process, so a `spawnSync` would hold the loop until the
 * child gave up on its own 15s timeout and never answer it.
 */
function run(args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1', INTERNAL_API_KEY: 'test-key', NODE_OPTIONS: '', ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => { stdout += c.toString('utf8'); });
    child.stderr.on('data', (c: Buffer) => { stderr += c.toString('utf8'); });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function help(...argv: string[]): string {
  const r = spawnSync(process.execPath, [CLI, ...argv, '--help'], {
    encoding: 'utf8', timeout: 30_000, env: { ...process.env, NO_COLOR: '1', NODE_OPTIONS: '' },
  });
  return (r.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');
}

/** The coverage inventory of the RUNNING build — never a copy, never a re-read of src/. */
function builtInventory(): {
  CHECK_METHOD_PREFIXES: Record<string, readonly string[]>;
  UNREACHABLE_PREFIXES: readonly string[];
} {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require(path.join(REPO_ROOT, 'dist', 'hardening', 'coverage-ledger.js'));
}

/** A registry that lists one stub and accepts the PATCH. */
async function happyRegistry(over: Partial<Record<string, string>> = {}): Promise<MockRegistry> {
  return startMockRegistry((req) => {
    if (req.method === 'GET') {
      return { status: 200, body: JSON.stringify({ stubs: [stubRow({ id: STUB_ID, checkId: RECORDED_CHECK_ID, ...over })], total: 1 }) };
    }
    return { status: 200, body: JSON.stringify({ ok: true }) };
  });
}

const patches = (reqs: RecordedRequest[]) => reqs.filter(r => r.method === 'PATCH');

describe('HMA-08.AC3 the command surface', () => {
  it('HMA-08.AC3 registers mark-stub <id> <status> as a visible top-level command', () => {
    if (!canRun()) return;
    expect(help()).toContain('mark-stub');
    expect(help('mark-stub')).toContain('Usage: hackmyagent mark-stub [options] <id> <status>');
  });

  it('HMA-08.AC3 opens its long description with the INTERNAL_API_KEY requirement', () => {
    if (!canRun()) return;
    const text = help('mark-stub');
    const afterUsage = text.split('\n').slice(1).map(l => l.trim()).filter(Boolean);
    expect(afterUsage[0]).toMatch(/^Requires INTERNAL_API_KEY/);
  });

  it('HMA-08.AC3 carries --registry-url and --json in exact parity with pull-stubs', () => {
    if (!canRun()) return;
    const optionLine = (command: string, flag: string): string => {
      const text = help(command);
      const options = text.slice(text.indexOf('\nOptions:'));
      const line = options.split('\n').find(l => l.trim().startsWith(flag));
      expect(line, `${command} does not register ${flag}`).toBeDefined();
      return line!.replace(/\s+/g, ' ').trim();
    };
    // Same declaration, same default, same wording — a write-back that talks
    // to a different registry than the read it followed is the one failure
    // this parity is for.
    expect(optionLine('mark-stub', '--registry-url')).toBe(optionLine('pull-stubs', '--registry-url'));
    expect(optionLine('mark-stub', '--json')).toContain('--json');
    expect(help('mark-stub')).toContain('--dry-run');
    expect(help('mark-stub')).toContain('--reason <text>');
    expect(help('mark-stub')).toContain('--source-commit <sha>');
    expect(help('mark-stub')).toContain('--check-id <id>');
  });

  it('HMA-08.AC3 PATCHes /internal/aria/hma-stubs/:id with the camelCase body', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run(['mark-stub', STUB_ID, 'reviewed', '--registry-url', registry.url]);

    expect(res.status, res.stderr).toBe(0);
    const sent = patches(registry.requests);
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe(`/internal/aria/hma-stubs/${STUB_ID}`);
    expect(JSON.parse(sent[0].body)).toEqual({ status: 'reviewed' });
  });

  it('HMA-08.AC3 carries reason and evidence in the same camelCase body', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run([
      'mark-stub', STUB_ID, 'integrated',
      '--source-commit', COMMIT, '--reason', 'shipped as CRED-001',
      '--registry-url', registry.url,
    ]);

    expect(res.status, res.stderr).toBe(0);
    expect(JSON.parse(patches(registry.requests)[0].body)).toEqual({
      status: 'integrated',
      reason: 'shipped as CRED-001',
      evidence: { checkId: RECORDED_CHECK_ID, hmaVersion: VERSION, sourceCommit: COMMIT, reachable: true },
    });
  });

  it('HMA-08.AC3 validates --source-commit as 7-40 hex', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const tooShort = await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', 'a1b2c3', '--registry-url', registry.url, '--json']);
    const notHex = await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', 'zzzzzzzz', '--registry-url', registry.url, '--json']);
    const tooLong = await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', 'a'.repeat(41), '--registry-url', registry.url, '--json']);
    const fullSha = await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', 'a'.repeat(40), '--registry-url', registry.url, '--json']);

    for (const bad of [tooShort, notHex, tooLong]) {
      expect(bad.status).toBe(1);
      expect(JSON.parse(bad.stdout).refusal.code).toBe('source-commit-shape');
    }
    expect(fullSha.status, fullSha.stderr).toBe(0);
  });

  it('HMA-08.AC3 defaults --check-id to the stub\'s own recorded checkId via the existing GET', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry((req) => {
      if (req.method === 'GET') {
        return { status: 200, body: JSON.stringify({ stubs: [stubRow({ id: STUB_ID, checkId: 'MCP-014' })], total: 1 }) };
      }
      return { status: 200, body: '{}' };
    });

    const res = await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT, '--registry-url', registry.url, '--json']);

    expect(res.status, res.stderr).toBe(0);
    expect(registry.requests[0].method).toBe('GET');
    expect(registry.requests[0].url).toBe('/internal/aria/hma-stubs');
    expect(JSON.parse(res.stdout).evidence.checkId).toBe('MCP-014');
  });
});

describe('HMA-08.AC4 the evidence is honest by construction', () => {
  it('HMA-08.AC4 refuses integrated without --source-commit, and sends nothing', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run(['mark-stub', STUB_ID, 'integrated', '--registry-url', registry.url, '--json']);

    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).refusal.code).toBe('source-commit-required');
    expect(patches(registry.requests)).toHaveLength(0);
  });

  it('HMA-08.AC4 refuses rejected without --reason, and sends nothing', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run(['mark-stub', STUB_ID, 'rejected', '--registry-url', registry.url, '--json']);

    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).refusal.code).toBe('reason-required');
    expect(patches(registry.requests)).toHaveLength(0);
  });

  it('HMA-08.AC4 refuses an unreachable-class checkId, on a fixture derived from the built UNREACHABLE_PREFIXES', async () => {
    if (!canRun()) return;
    const { UNREACHABLE_PREFIXES } = builtInventory();
    // Non-vacuity: if the list is ever emptied — which is what wiring all
    // three checks in would mean — this test has no subject and must say so
    // rather than pass over an absence.
    expect(UNREACHABLE_PREFIXES.length, 'the built module lists no unreachable prefixes').toBeGreaterThan(0);
    const fixture = `${UNREACHABLE_PREFIXES[0]}-001`;
    registry = await happyRegistry();

    const res = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--check-id', fixture, '--registry-url', registry.url, '--json',
    ]);

    expect(res.status).toBe(1);
    const envelope = JSON.parse(res.stdout);
    expect(envelope.refusal.code).toBe('check-unreachable');
    expect(envelope.refusal.what).toContain(UNREACHABLE_PREFIXES[0]);
    expect(patches(registry.requests)).toHaveLength(0);
  });

  it('HMA-08.AC4 refuses a checkId absent from the built coverage inventory', async () => {
    if (!canRun()) return;
    const { CHECK_METHOD_PREFIXES, UNREACHABLE_PREFIXES } = builtInventory();
    const known = new Set([...Object.values(CHECK_METHOD_PREFIXES).flat(), ...UNREACHABLE_PREFIXES]);
    const absent = 'NOSUCHFAMILY';
    expect(known.has(absent), 'the fixture prefix is registered after all').toBe(false);
    registry = await happyRegistry();

    const res = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--check-id', `${absent}-001`, '--registry-url', registry.url, '--json',
    ]);

    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).refusal.code).toBe('check-absent');
    expect(patches(registry.requests)).toHaveLength(0);
  });

  it('HMA-08.AC4 derives hmaVersion only from the running artifact\'s own version', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    // A version the environment offers loudly, which the evidence must ignore.
    const res = await run(
      ['mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT, '--registry-url', registry.url, '--json'],
      { npm_package_version: '99.99.99', HMA_VERSION: '99.99.99' },
    );

    expect(res.status, res.stderr).toBe(0);
    expect(JSON.parse(res.stdout).evidence.hmaVersion).toBe(VERSION);
    expect(JSON.parse(patches(registry.requests)[0].body).evidence.hmaVersion).toBe(VERSION);
  });

  it('HMA-08.AC4 offers no --evidence, --reachable or --hma-version flag anywhere on the option surface', async () => {
    if (!canRun()) return;
    const text = help('mark-stub');
    for (const flag of ['--evidence', '--reachable', '--hma-version']) {
      expect(text, `${flag} is on the option surface`).not.toContain(flag);
      const res = await run(['mark-stub', STUB_ID, 'reviewed', flag, 'x']);
      expect(res.stderr).toContain(`unknown option '${flag}'`);
    }
  });
});

describe('HMA-08.AC5 exit codes and output contracts', () => {
  it('HMA-08.AC5 exits 0 when the transition is recorded', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();
    const res = await run(['mark-stub', STUB_ID, 'reviewed', '--registry-url', registry.url]);
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toContain('Recorded');
  });

  it('HMA-08.AC5 exits 1 when the local preflight refuses', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();
    const res = await run(['mark-stub', STUB_ID, 'rejected', '--registry-url', registry.url]);
    expect(res.status).toBe(1);
  });

  it('HMA-08.AC5 exits 1 when the registry answers 4xx', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry((req) => {
      if (req.method === 'GET') return { status: 200, body: JSON.stringify({ stubs: [stubRow({ id: STUB_ID })], total: 1 }) };
      return { status: 409, body: '{"error":"illegal transition draft -> reviewed"}' };
    });

    const res = await run(['mark-stub', STUB_ID, 'reviewed', '--registry-url', registry.url]);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain('illegal transition');
  });

  it('HMA-08.AC5 exits 2 when the registry answers 5xx — the run cannot tell whether it landed', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry((req) => {
      if (req.method === 'GET') return { status: 200, body: JSON.stringify({ stubs: [stubRow({ id: STUB_ID })], total: 1 }) };
      return { status: 503, body: 'upstream unavailable' };
    });

    const res = await run(['mark-stub', STUB_ID, 'reviewed', '--registry-url', registry.url]);

    expect(res.status).toBe(2);
    expect(res.stderr).toContain('Not settled');
  });

  it('HMA-08.AC5 exits 2 when the registry cannot be reached at all', async () => {
    if (!canRun()) return;
    const dead = await closedPortUrl();
    const res = await run(['mark-stub', STUB_ID, 'reviewed', '--registry-url', dead]);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('Not settled');
  });

  it('HMA-08.AC5 emits the camelCase envelope under --json on both the recorded and refused paths', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const ok = JSON.parse((await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--reason', 'shipped', '--registry-url', registry.url, '--json',
    ])).stdout);
    expect(ok.ok).toBe(true);
    expect(ok.stubId).toBe(STUB_ID);
    expect(ok.status).toBe('integrated');
    expect(ok.checkId).toBe(RECORDED_CHECK_ID);
    expect(ok.reason).toBe('shipped');
    expect(ok.evidence).toEqual({ checkId: RECORDED_CHECK_ID, hmaVersion: VERSION, sourceCommit: COMMIT, reachable: true });
    expect(ok.refusal).toBeUndefined();

    const refused = JSON.parse((await run(['mark-stub', STUB_ID, 'rejected', '--registry-url', registry.url, '--json'])).stdout);
    expect(refused.ok).toBe(false);
    expect(refused.stubId).toBe(STUB_ID);
    expect(refused.status).toBe('rejected');
    expect(Object.keys(refused.refusal).sort()).toEqual(['code', 'fix', 'verify', 'what']);
    expect(refused).toHaveProperty('checkId');
  });

  it('HMA-08.AC5 renders a refusal as WHAT + Verify: + Fix: with no bypass flag offered', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run(['mark-stub', STUB_ID, 'integrated', '--registry-url', registry.url]);

    const lines = res.stderr.split('\n').filter(Boolean);
    expect(lines[0]).toMatch(/^Refused: \S/);
    expect(lines[1]).toMatch(/^\s+Verify: \S/);
    expect(lines[2]).toMatch(/^\s+Fix: \S/);
    // A gate with a bypass measures how many people found the bypass.
    for (const bypass of ['--force', '--no-verify', '--skip', '--yes', '--evidence', '--reachable']) {
      expect(res.stderr, `the refusal offers ${bypass}`).not.toContain(bypass);
    }
  });

  it('HMA-08.AC5 cites only flags that resolve against the registered Commander surface', async () => {
    if (!canRun()) return;
    // Phase 7c cross-reference, scoped to this command: `--dry-run` printed as
    // advice is a dead end unless `mark-stub` registers it. The repo-wide
    // walker (__tests__/ui/printed-flag-citations.test.ts) enforces the same
    // rule over every string in src/ and docs/; this asserts it where the new
    // strings are, so a break here names the command that broke.
    const registered = (command: string): Set<string> => {
      const text = help(command);
      const options = text.slice(text.indexOf('\nOptions:'));
      return new Set([...options.matchAll(/--[a-z][\w-]*/g)].map(m => m[0]));
    };
    const markStubFlags = registered('mark-stub');
    const pullStubsFlags = registered('pull-stubs');
    const secureFlags = registered('secure');
    const checkMetadataFlags = registered('check-metadata');
    expect(markStubFlags.size).toBeGreaterThan(4);

    registry = await happyRegistry();
    const refusals = [
      await run(['mark-stub', STUB_ID, 'integrated', '--registry-url', registry.url]),
      await run(['mark-stub', STUB_ID, 'rejected', '--registry-url', registry.url]),
      await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', 'zzz', '--registry-url', registry.url]),
      await run(['mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT, '--check-id', 'NOSUCHFAMILY-001', '--registry-url', registry.url]),
    ];

    const unresolved: string[] = [];
    for (const text of [help('mark-stub'), ...refusals.map(r => r.stderr)]) {
      for (const segment of text.split('\n')) {
        // The command a flag is attributed to is the one named on its own
        // line; a line naming none is prose about this command.
        const owner = /\bpull-stubs\b/.test(segment) ? pullStubsFlags
          : /\bcheck-metadata\b/.test(segment) ? checkMetadataFlags
            : /\bsecure\b/.test(segment) ? secureFlags
              : markStubFlags;
        for (const m of segment.matchAll(/(?<![\w-])--[a-z][\w-]*/g)) {
          if (!owner.has(m[0])) unresolved.push(`${m[0]} in: ${segment.trim()}`);
        }
      }
    }
    expect(unresolved, unresolved.join('\n')).toEqual([]);
  });
});

describe('HMA-08.AC6 --dry-run runs every gate and sends nothing', () => {
  it('HMA-08.AC6 makes zero HTTP calls when it needs no lookup', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const res = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--check-id', RECORDED_CHECK_ID, '--dry-run', '--registry-url', registry.url,
    ]);

    expect(res.status, res.stderr).toBe(0);
    expect(registry.requests, 'a dry run touched the network').toHaveLength(0);
  });

  it('HMA-08.AC6 prints the exact PATCH body it would have sent', async () => {
    if (!canRun()) return;
    registry = await happyRegistry();

    const preview = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT, '--reason', 'shipped',
      '--check-id', RECORDED_CHECK_ID, '--dry-run', '--registry-url', registry.url,
    ]);
    const real = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT, '--reason', 'shipped',
      '--check-id', RECORDED_CHECK_ID, '--registry-url', registry.url,
    ]);

    expect(preview.stdout).toContain('nothing was sent');
    const previewed = JSON.parse(preview.stdout.slice(preview.stdout.indexOf('{')));
    // "Exact" means byte-for-byte the same object the real run puts on the
    // wire, not a summary of it.
    expect(previewed).toEqual(JSON.parse(patches(registry.requests)[0].body));
    expect(real.status, real.stderr).toBe(0);
  });

  it('HMA-08.AC6 still runs the reachability probe, and its exit code reflects the local verdict', async () => {
    if (!canRun()) return;
    const { UNREACHABLE_PREFIXES } = builtInventory();
    expect(UNREACHABLE_PREFIXES.length).toBeGreaterThan(0);
    registry = await happyRegistry();

    const refused = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--check-id', `${UNREACHABLE_PREFIXES[0]}-001`, '--dry-run', '--registry-url', registry.url, '--json',
    ]);
    const passes = await run([
      'mark-stub', STUB_ID, 'integrated', '--source-commit', COMMIT,
      '--check-id', RECORDED_CHECK_ID, '--dry-run', '--registry-url', registry.url, '--json',
    ]);

    expect(refused.status).toBe(1);
    expect(JSON.parse(refused.stdout).refusal.code).toBe('check-unreachable');
    expect(passes.status, passes.stderr).toBe(0);
    expect(registry.requests).toHaveLength(0);
  });

  it('HMA-08.AC6 warns on an obviously illegal source transition and defers to the registry as the authority', async () => {
    if (!canRun()) return;
    // The stub is already settled as `integrated`; moving it back to `draft`
    // is the fat-finger this warns about. It is a WARNING, not a refusal —
    // the registry owns the transition table, and a CLI holding its own copy
    // is the second vocabulary this whole unit deletes.
    registry = await happyRegistry({ status: 'integrated' });

    const res = await run(['mark-stub', STUB_ID, 'draft', '--registry-url', registry.url]);

    expect(res.status, res.stderr).toBe(0);
    expect(res.stderr).toContain('Warning');
    expect(res.stderr).toMatch(/registry decides which transitions are legal/);
    expect(res.stderr).not.toContain('Refused');
    expect(patches(registry.requests)).toHaveLength(1);
  });
});
