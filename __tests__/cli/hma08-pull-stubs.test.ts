/**
 * HMA-08.AC1 / HMA-08.AC2 — `pull-stubs` stops holding an opinion about the
 * status vocabulary, and starts printing the identifier its own next step
 * needs.
 *
 * DEFECT 1 of `todo/roadmap/hackmyagent-pull-stubs-status-vocabulary-mismatch.md`:
 * the CLI validated `--status` against a hardcoded
 * `['draft','review','integrated','rejected']` AND filtered the response
 * against the same list, while the DB CHECK constraint held a different set.
 * Every value except the default was unusable in one direction or the other,
 * so the pipeline's only working query was the default — the loop's terminus,
 * untraversable. [CHIEF-CA] 2026-08-31 ruled ONE vocabulary owned by the DB
 * and the Go domain constants, with the CLI array and the client filter
 * DELETED.
 *
 * The registry leg is REG-10; this suite runs against the in-process mock, so
 * neither leg waits for the other. Spawn-based like its siblings in this
 * directory, and gated on a built CLI through `assertDistFreshIfPresent`
 * (#285) so it can never measure a stale binary and report a pass.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { startMockRegistry, stubRow, type MockRegistry } from '../helpers/hma08-stub-registry';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const canRun = () => existsSync(CLI);

let registry: MockRegistry | undefined;
afterEach(async () => { await registry?.close(); registry = undefined; });

/**
 * Spawn the built CLI WITHOUT blocking this process's event loop.
 *
 * `spawnSync` cannot be used here: the mock registry runs in-process, and a
 * synchronous spawn holds the loop until the child exits — so the child's
 * request sits in the socket buffer unanswered until its own 15s timeout
 * fires. Every test in the first draft of this file failed that way, with the
 * request recorded and the answer never sent.
 */
function run(args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1', INTERNAL_API_KEY: 'test-key', NODE_OPTIONS: '' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => { stdout += c.toString('utf8'); });
    child.stderr.on('data', (c: Buffer) => { stderr += c.toString('utf8'); });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

/** `--help` text, ANSI-stripped. */
function help(command: string): string {
  const r = spawnSync(process.execPath, [CLI, command, '--help'], {
    encoding: 'utf8', timeout: 30_000, env: { ...process.env, NO_COLOR: '1', NODE_OPTIONS: '' },
  });
  return (r.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');
}

describe('HMA-08.AC1 the status vocabulary belongs to the registry', () => {
  it('HMA-08.AC1 passes an arbitrary unknown status through to the server as ?status=, unvalidated', async () => {
    if (!canRun()) return;
    // Not a word any vocabulary this project has ever held. On the pre-fix
    // build this exited 1 before a socket was opened.
    const arbitrary = 'wibble-wobble-9000';
    registry = await startMockRegistry(() => ({
      status: 200,
      body: JSON.stringify({ stubs: [stubRow({ status: arbitrary })], total: 1 }),
    }));

    const res = await run(['pull-stubs', '--status', arbitrary, '--registry-url', registry.url, '--json']);

    expect(res.status, res.stderr).toBe(0);
    expect(registry.requests).toHaveLength(1);
    expect(registry.requests[0].url).toBe(
      `/internal/aria/hma-stubs?status=${encodeURIComponent(arbitrary)}`,
    );
    // And no client-side filter ate the answer on the way back.
    const payload = JSON.parse(res.stdout) as { stubs: unknown[]; filtered: number };
    expect(payload.filtered).toBe(1);
    expect(payload.stubs).toHaveLength(1);
  });

  it('HMA-08.AC1 renders rows the registry returned even when their status differs from the one asked for', async () => {
    if (!canRun()) return;
    // The registry is the authority on what matched. A client that re-filters
    // can only ever disagree with it, and disagreeing silently is what made
    // `--status review` return nothing against rows that existed.
    registry = await startMockRegistry(() => ({
      status: 200,
      body: JSON.stringify({ stubs: [stubRow({ id: 'kept-me', status: 'something-else' })], total: 1 }),
    }));

    const res = await run(['pull-stubs', '--status', 'reviewed', '--registry-url', registry.url]);

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toContain('kept-me');
  });

  it('HMA-08.AC1 renders a 4xx body near-verbatim, because that body carries the allowed set', async () => {
    if (!canRun()) return;
    // Deliberately longer than the 200-byte clip the pre-fix build applied:
    // the allowed set is the one thing the CLI no longer knows, so truncating
    // the answer that carries it defeats the whole ruling.
    const allowed = 'status must be one of: draft, reviewed, integrated, rejected';
    const filler = 'x'.repeat(240);
    const body = `{"error":"invalid status","detail":"${filler}","allowed":"${allowed}"}`;
    expect(body.length).toBeGreaterThan(200);
    registry = await startMockRegistry(() => ({ status: 400, body }));

    const res = await run(['pull-stubs', '--status', 'nope', '--registry-url', registry.url]);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain(allowed);
    expect(res.stderr).toContain(filler);
  });

  it('HMA-08.AC1 carries no client-side status vocabulary in the source', () => {
    const src = readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf8');
    const start = src.indexOf(".command('pull-stubs')");
    const end = src.indexOf(".command('mark-stub')");
    expect(start, 'pull-stubs registration not found').toBeGreaterThan(-1);
    expect(end, 'mark-stub registration not found').toBeGreaterThan(start);
    const region = src.slice(start, end);
    expect(region).not.toContain('validStatuses');
    expect(region, 'the client-side status filter is back').not.toMatch(/\.filter\([^)]*\.status\s*===/);
  });

  it('HMA-08.AC1 lists the four ruled words in --status help as examples of the current vocabulary', () => {
    if (!canRun()) return;
    const text = help('pull-stubs');
    // Sliced out of the Options block, not the whole page: `--all` and
    // `--json` appear in the Examples above it, so an unanchored slice reads
    // backwards and passes over an empty string.
    const options = text.slice(text.indexOf('\nOptions:'));
    const statusHelp = options.slice(options.indexOf('--status <status>'), options.indexOf('--all'));
    expect(statusHelp, 'the --status option block was not found').not.toBe('');
    for (const word of ['draft', 'reviewed', 'integrated', 'rejected']) {
      expect(statusHelp, `--status help does not name ${word}`).toContain(word);
    }
  });
});

describe('HMA-08.AC2 the report leads with the identifier its next step needs', () => {
  it('HMA-08.AC2 leads each formatted stub with a Stub ID field', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry(() => ({
      status: 200,
      body: JSON.stringify({ stubs: [stubRow({ id: 'stub-abc-123' })], total: 1 }),
    }));

    const res = await run(['pull-stubs', '--registry-url', registry.url]);

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toContain('Stub ID:');
    expect(res.stdout).toContain('stub-abc-123');
    // FIRST field of the block, ahead of the Check ID that used to lead it.
    expect(res.stdout.indexOf('Stub ID:')).toBeLessThan(res.stdout.indexOf('Check ID:'));
  });

  it('HMA-08.AC2 closes the summary with one next-step line naming mark-stub', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry(() => ({
      status: 200,
      body: JSON.stringify({ stubs: [stubRow()], total: 1 }),
    }));

    const res = await run(['pull-stubs', '--registry-url', registry.url]);

    const naming = res.stdout.split('\n').filter(l => l.includes('mark-stub'));
    expect(naming, 'expected exactly one next-step line naming mark-stub').toHaveLength(1);
    expect(naming[0]).toMatch(/Next step/);
    expect(res.stdout.indexOf('Summary')).toBeLessThan(res.stdout.indexOf('mark-stub'));
  });

  it('HMA-08.AC2 --all omits the status parameter from the request entirely', async () => {
    if (!canRun()) return;
    registry = await startMockRegistry(() => ({
      status: 200,
      body: JSON.stringify({ stubs: [stubRow(), stubRow({ id: 'two', status: 'integrated' })], total: 2 }),
    }));

    const res = await run(['pull-stubs', '--all', '--registry-url', registry.url, '--json']);

    expect(res.status, res.stderr).toBe(0);
    expect(registry.requests).toHaveLength(1);
    // A request-shape switch, not a magic vocabulary value: no `status` key
    // reaches the wire at all, so the registry needs no word for "any".
    expect(registry.requests[0].url).toBe('/internal/aria/hma-stubs');
    expect(registry.requests[0].url).not.toContain('status');
    const payload = JSON.parse(res.stdout) as { filtered: number; status: string | null; all: boolean };
    expect(payload.filtered).toBe(2);
    expect(payload.status).toBeNull();
    expect(payload.all).toBe(true);
  });
});
