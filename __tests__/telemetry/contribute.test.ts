/**
 * Tests for community contribution module.
 *
 * Verifies:
 *   - Queue-based event storage (compatible with @opena2a/contribute format)
 *   - Scan event summary structure (no PII, no file paths)
 *   - Contributor token is stable across calls
 *   - Flush submits to correct endpoint
 *   - Delayed consent tip after 3rd scan
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  getContributorToken,
  generateContributorToken,
  buildScanEvent,
  buildContributionPayloadFromDir,
  queueEvent,
  queueAndMaybeFlush,
  flushQueue,
  submitContribution,
  _setRegistryHealthProbe,
  _resetRegistryHealthProbe,
  type ContributionEvent,
} from '../../src/telemetry/contribute';
import {
  getQueuedEvents,
  clearQueue as sharedClearQueue,
} from '@opena2a/contribute';
import {
  recordScanAndMaybeShowTip,
  isContributeEnabled,
  shouldPromptContribute,
  incrementScanCount,
  saveContributeChoice,
  _resetBackend,
} from '../../src/telemetry/opt-in';
import type { SecurityFinding } from '../../src/hardening';

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'contribute-test-'));
}

/** The real `~/.opena2a` this run must not write into. See the beforeAll below. */
const REAL_OPENA2A_DIR = path.join(os.homedir(), '.opena2a');

/**
 * Registry base URL for the flush tests. Loopback discard port: nothing is
 * listening and nothing routes off the machine, so a regression that puts a
 * real request back on this path fails loudly instead of passing against the
 * production registry. The health probe is stubbed as well -- this is the
 * belt to that brace.
 */
const UNROUTABLE_REGISTRY_URL = 'http://127.0.0.1:9';

/**
 * mtime of a file, or null when it does not exist. Either answer is a fine
 * baseline — the assertion is that it is the SAME answer afterwards.
 */
function mtimeOrNull(p: string): number | null {
  try {
    return fs.statSync(p).mtimeMs;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------
// Hermeticity: a per-run scratch OPENA2A_HOME for the whole file
// ---------------------------------------------------------------
//
// Recorded for HMA-20.AC3: the scratch home is set HERE, in this file, not in
// vitest.setup.ts. Both were allowed; this file is the smaller blast radius,
// because vitest.setup.ts is loaded by all 373 test files in the suite and two
// sibling branches are editing test files right now.
//
// src/telemetry/contribute.ts honours OPENA2A_HOME for all three of the files
// it owns — contribute-health.json, contribute-retry.json, contribute-ping.json
// — and reads the variable lazily inside each path helper, so setting it in a
// hook (rather than before the import) is enough.
//
// KNOWN LIMIT, deliberately left: `@opena2a/contribute`'s dist/queue.js binds
// `QUEUE_PATH = join(homedir(), '.opena2a', 'contribute-queue.json')` at module
// load and never consults OPENA2A_HOME, so `queueEvent`/`clearQueue` in this
// file still touch the developer's real ~/.opena2a/contribute-queue.json. That
// is a change to the published package, not to this repository, and is out of
// HMA-20's scope. The same is true of contributor-salt via dist/contributor.js.
//
// The nested describes that set their own OPENA2A_HOME still work: they capture
// the value on entry (which is this scratch dir) and restore it on exit.
let suiteHome: string;
let suiteHomeOriginalEnv: string | undefined;

beforeAll(() => {
  suiteHome = createTempDir();
  suiteHomeOriginalEnv = process.env.OPENA2A_HOME;
  process.env.OPENA2A_HOME = suiteHome;
});

afterAll(() => {
  if (suiteHomeOriginalEnv === undefined) {
    delete process.env.OPENA2A_HOME;
  } else {
    process.env.OPENA2A_HOME = suiteHomeOriginalEnv;
  }
  cleanupDir(suiteHome);
});

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Sample findings with full detail (file paths, line numbers, descriptions, fix text).
 * The contribution module must strip all of this into summary stats only.
 */
function makeSampleFindings(): SecurityFinding[] {
  return [
    {
      checkId: 'CRED-001',
      name: 'Hardcoded API key',
      description: 'Found hardcoded API key in src/config.ts',
      category: 'credentials',
      severity: 'critical' as const,
      passed: false,
      message: 'API key sk-1234 found in source code',
      fixable: true,
      fixed: false,
      file: 'src/config.ts',
      line: 42,
      fix: 'Remove the key and use environment variables',
      details: { keyPattern: 'sk-*', context: 'const key = "sk-1234"' },
    },
    {
      checkId: 'MCP-003',
      name: 'MCP server config',
      description: 'MCP server config is world-readable',
      category: 'mcp',
      severity: 'high' as const,
      passed: false,
      message: 'File permissions are 0644',
      fixable: true,
      fixed: false,
      file: '.mcp/config.json',
      line: 1,
      fix: 'chmod 600 .mcp/config.json',
    },
    {
      checkId: 'GIT-001',
      name: 'Gitignore coverage',
      description: '.gitignore covers secrets',
      category: 'git',
      severity: 'low' as const,
      passed: true,
      message: 'OK',
      fixable: false,
    },
    {
      checkId: 'NET-002',
      name: 'TLS configuration',
      description: 'TLS is properly configured',
      category: 'network',
      severity: 'medium' as const,
      passed: true,
      message: 'TLS 1.3 enabled',
      fixable: false,
    },
  ] as SecurityFinding[];
}

// ---------------------------------------------------------------
// getContributorToken
// ---------------------------------------------------------------

describe('getContributorToken', () => {
  // The shared library (@opena2a/contribute) uses ~/.opena2a/ directly
  // (not OPENA2A_HOME), so we test against the real home directory.
  const opena2aDir = path.join(os.homedir(), '.opena2a');

  it('returns a 64-character hex string (SHA-256)', () => {
    const token = getContributorToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is stable across calls (same device, same salt)', () => {
    const token1 = getContributorToken();
    const token2 = getContributorToken();
    expect(token1).toBe(token2);
  });

  it('creates contributor-salt file in ~/.opena2a/', () => {
    getContributorToken();
    const saltPath = path.join(opena2aDir, 'contributor-salt');
    expect(fs.existsSync(saltPath)).toBe(true);
    const salt = fs.readFileSync(saltPath, 'utf-8').trim();
    expect(salt).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is aliased as generateContributorToken', () => {
    expect(generateContributorToken).toBe(getContributorToken);
  });
});

// ---------------------------------------------------------------
// buildScanEvent
// ---------------------------------------------------------------

describe('buildScanEvent', () => {
  let tmpHome: string;
  let tmpDir: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    tmpDir = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    cleanupDir(tmpHome);
    cleanupDir(tmpDir);
  });

  it('produces a ContributionEvent with summary stats', () => {
    const findings = makeSampleFindings();
    const event = buildScanEvent('@test/my-agent', tmpDir, findings, 1200);

    expect(event.type).toBe('scan_result');
    expect(event.tool).toBe('hackmyagent');
    expect(event.toolVersion).toBeDefined();
    expect(event.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(event.package?.name).toBe('@test/my-agent');
    expect(event.scanSummary).toBeDefined();
    expect(event.scanSummary!.totalChecks).toBe(4);
    expect(event.scanSummary!.passed).toBe(2);
    expect(event.scanSummary!.critical).toBe(1);
    expect(event.scanSummary!.high).toBe(1);
    expect(event.scanSummary!.medium).toBe(0);
    expect(event.scanSummary!.low).toBe(0);
    expect(event.scanSummary!.durationMs).toBe(1200);
    expect(event.scanSummary!.score).toBe(50);
    expect(event.scanSummary!.verdict).toBe('fail');
  });

  it('strips all PII -- no file paths, line numbers, descriptions', () => {
    const findings = makeSampleFindings();
    const event = buildScanEvent('test', tmpDir, findings, 500);
    const json = JSON.stringify(event);

    expect(json).not.toContain('src/config.ts');
    expect(json).not.toContain('.mcp/config.json');
    expect(json).not.toContain('Hardcoded API key');
    expect(json).not.toContain('world-readable');
    expect(json).not.toContain('sk-1234');
    expect(json).not.toContain('chmod');
    expect(json).not.toContain('keyPattern');
  });

  it('detects npm ecosystem from package.json', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'test', version: '2.0.0' }),
    );

    const event = buildScanEvent('test', tmpDir, [], 100);
    expect(event.package?.ecosystem).toBe('npm');
    expect(event.package?.version).toBe('2.0.0');
  });

  it('detects pypi ecosystem from setup.py', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'setup.py'),
      'setup(name="test", version="3.1.0")',
    );

    const event = buildScanEvent('test', tmpDir, [], 100);
    expect(event.package?.ecosystem).toBe('pypi');
    expect(event.package?.version).toBe('3.1.0');
  });

  it('falls back to github ecosystem', () => {
    const event = buildScanEvent('test', tmpDir, [], 100);
    expect(event.package?.ecosystem).toBe('github');
  });

  it('handles empty findings array', () => {
    const event = buildScanEvent('test', tmpDir, [], 100);
    expect(event.scanSummary!.totalChecks).toBe(0);
    expect(event.scanSummary!.passed).toBe(0);
    expect(event.scanSummary!.score).toBe(0);
  });

  it('computes verdict "pass" when no critical/high failures', () => {
    const findings: SecurityFinding[] = [
      {
        checkId: 'LOW-001', name: 'x', description: '', category: 'test',
        severity: 'low', passed: false, message: '', fixable: false,
      } as SecurityFinding,
    ];
    const event = buildScanEvent('test', tmpDir, findings, 100);
    expect(event.scanSummary!.verdict).toBe('pass');
  });

  it('computes verdict "warn" when high failures exist', () => {
    const findings: SecurityFinding[] = [
      {
        checkId: 'HIGH-001', name: 'x', description: '', category: 'test',
        severity: 'high', passed: false, message: '', fixable: false,
      } as SecurityFinding,
    ];
    const event = buildScanEvent('test', tmpDir, findings, 100);
    expect(event.scanSummary!.verdict).toBe('warn');
  });
});

// ---------------------------------------------------------------
// buildContributionPayloadFromDir (legacy compat)
// ---------------------------------------------------------------

describe('buildContributionPayloadFromDir', () => {
  let tmpHome: string;
  let tmpDir: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    tmpDir = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    cleanupDir(tmpHome);
    cleanupDir(tmpDir);
  });

  it('returns a ContributionEvent (delegates to buildScanEvent)', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'test', version: '2.0.0' }),
    );

    const payload = buildContributionPayloadFromDir('test', tmpDir, []);
    expect(payload.type).toBe('scan_result');
    expect(payload.tool).toBe('hackmyagent');
    expect(payload.package?.ecosystem).toBe('npm');
  });
});

// ---------------------------------------------------------------
// Queue operations
// ---------------------------------------------------------------

describe('queueEvent', () => {
  beforeEach(() => {
    sharedClearQueue();
  });

  afterEach(() => {
    sharedClearQueue();
  });

  it('queues events via shared library', () => {
    const event: ContributionEvent = {
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
      package: { name: 'test' },
      scanSummary: {
        totalChecks: 10, passed: 8, critical: 0, high: 1,
        medium: 1, low: 0, score: 80, verdict: 'warn', durationMs: 500,
      },
    };

    queueEvent(event);

    const events = getQueuedEvents();
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[events.length - 1];
    expect(last.tool).toBe('hackmyagent');
  });

  it('appends multiple events', () => {
    const makeEvent = (name: string): ContributionEvent => ({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
      package: { name },
      scanSummary: {
        totalChecks: 5, passed: 5, critical: 0, high: 0,
        medium: 0, low: 0, score: 100, verdict: 'pass', durationMs: 200,
      },
    });

    queueEvent(makeEvent('pkg-a'));
    queueEvent(makeEvent('pkg-b'));

    const events = getQueuedEvents();
    expect(events.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------
// flushQueue (with mocked fetch AND a stubbed health probe)
// ---------------------------------------------------------------
//
// `flushQueue` will not call `submitBatch` until its pre-flight health probe
// says the registry is up, and that probe is a live node:https GET whose
// verdict is cached on disk for five minutes — the stubbed global `fetch` does
// not intercept it. Every test below therefore supplies its own verdict through
// `_setRegistryHealthProbe`. Nothing here reaches the network, and nothing here
// depends on what a previous run cached.

describe('flushQueue', () => {
  let healthProbe: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sharedClearQueue();
    // Default verdict for this block: registry is up. Individual tests read
    // `healthProbe.mock.calls` to assert whether the probe was consulted.
    healthProbe = vi.fn(async () => true);
    _setRegistryHealthProbe(healthProbe as never);
  });

  afterEach(() => {
    _resetRegistryHealthProbe();
    vi.unstubAllGlobals();
    sharedClearQueue();
  });

  it('HMA-20.AC1 submits batch to /api/v1/contribute endpoint', async () => {
    const response = { ok: true, json: async () => ({}) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    // Queue an event first
    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
      scanSummary: {
        totalChecks: 5, passed: 5, critical: 0, high: 0,
        medium: 0, low: 0, score: 100, verdict: 'pass', durationMs: 100,
      },
    });

    const ok = await flushQueue();

    expect(ok).toBe(true);
    // The probe was consulted for the default registry, and answered from the
    // stub above rather than from api.oa2a.org.
    expect(healthProbe).toHaveBeenCalledWith('https://api.oa2a.org');
    // A string comparison against a recorded mock call -- the stubbed `fetch`
    // never opened a connection to this URL.
    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://api.oa2a.org/api/v1/contribute');
    expect(fetchCall[1].method).toBe('POST');

    // Queue should be empty after successful flush
    const events = getQueuedEvents();
    expect(events).toHaveLength(0);
  });

  it('HMA-20.AC1 uses custom registry URL when provided', async () => {
    const response = { ok: true, json: async () => ({}) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    });

    // Deliberately unroutable: port 9 (discard) on loopback. If the seam ever
    // regresses and something here does open a socket, this test hangs or
    // refuses instead of quietly succeeding against a real host.
    await flushQueue(UNROUTABLE_REGISTRY_URL);

    expect(healthProbe).toHaveBeenCalledWith(UNROUTABLE_REGISTRY_URL);
    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe(`${UNROUTABLE_REGISTRY_URL}/api/v1/contribute`);
  });

  it('HMA-20.AC2 keeps events in queue on network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')));

    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    });

    const ok = await flushQueue(UNROUTABLE_REGISTRY_URL);
    expect(ok).toBe(false);

    // The failure came from the POST, not from the pre-flight probe: the probe
    // ran and said "healthy", so this is the submit path being exercised.
    expect(healthProbe).toHaveBeenCalledTimes(1);
    expect((fetch as any).mock.calls).toHaveLength(1);

    // Events should still be in queue
    const events = getQueuedEvents();
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it('HMA-20.AC3 returns true for empty queue without touching the real home', async () => {
    // The scratch home from the file-level beforeAll is in force, and it is not
    // the developer's ~/.opena2a.
    expect(process.env.OPENA2A_HOME).toBe(suiteHome);
    expect(process.env.OPENA2A_HOME).not.toBe(REAL_OPENA2A_DIR);

    const before = ['contribute-health.json', 'contribute-retry.json'].map(f =>
      mtimeOrNull(path.join(REAL_OPENA2A_DIR, f)),
    );

    const ok = await flushQueue();
    expect(ok).toBe(true);

    // Empty queue short-circuits ahead of the probe -- no verdict is needed,
    // so no health cache is consulted or written anywhere.
    expect(healthProbe).not.toHaveBeenCalled();

    const after = ['contribute-health.json', 'contribute-retry.json'].map(f =>
      mtimeOrNull(path.join(REAL_OPENA2A_DIR, f)),
    );
    expect(after).toEqual(before);
  });
});

// ---------------------------------------------------------------
// submitContribution (legacy compat)
// ---------------------------------------------------------------

// `submitContribution` is a thin wrapper over `flushQueue`, so it inherits the
// same pre-flight health probe and needs the same stub.
describe('submitContribution', () => {
  let healthProbe: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sharedClearQueue();
    healthProbe = vi.fn(async () => true);
    _setRegistryHealthProbe(healthProbe as never);
  });

  afterEach(() => {
    _resetRegistryHealthProbe();
    vi.unstubAllGlobals();
    sharedClearQueue();
  });

  it('HMA-20.AC1 queues event and flushes (legacy compat)', async () => {
    const response = { ok: true, json: async () => ({}) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    const event: ContributionEvent = {
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    };

    const result = await submitContribution(event, UNROUTABLE_REGISTRY_URL);
    expect(result.success).toBe(true);
    expect(healthProbe).toHaveBeenCalledWith(UNROUTABLE_REGISTRY_URL);
  });

  it('HMA-20.AC3 handles network errors gracefully, recording retry state under the scratch home', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')));

    const realRetry = path.join(REAL_OPENA2A_DIR, 'contribute-retry.json');
    const realRetryBefore = mtimeOrNull(realRetry);

    const event: ContributionEvent = {
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    };

    const result = await submitContribution(event, UNROUTABLE_REGISTRY_URL);
    expect(result.success).toBe(false);

    // The failed flush recorded backoff state. It landed in the scratch
    // OPENA2A_HOME, and the developer's copy was left alone.
    expect(fs.existsSync(path.join(suiteHome, 'contribute-retry.json'))).toBe(true);
    expect(mtimeOrNull(realRetry)).toBe(realRetryBefore);
  });
});

// ---------------------------------------------------------------
// recordScanAndMaybeShowTip (delayed consent)
// ---------------------------------------------------------------

describe('recordScanAndMaybeShowTip', () => {
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
    _resetBackend(); // Force local backend using OPENA2A_HOME
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    _resetBackend();
    cleanupDir(tmpHome);
  });

  it('returns null for first two scans', () => {
    expect(recordScanAndMaybeShowTip()).toBeNull();
    expect(recordScanAndMaybeShowTip()).toBeNull();
  });

  it('returns tip string on 3rd scan', () => {
    recordScanAndMaybeShowTip(); // scan 1
    recordScanAndMaybeShowTip(); // scan 2
    const tip = recordScanAndMaybeShowTip(); // scan 3
    expect(tip).not.toBeNull();
    expect(tip).toContain('community trust data');
    expect(tip).toContain('--contribute');
  });

  it('does not show tip if already opted in', () => {
    saveContributeChoice(true);
    recordScanAndMaybeShowTip(); // scan 1
    recordScanAndMaybeShowTip(); // scan 2
    const tip = recordScanAndMaybeShowTip(); // scan 3
    expect(tip).toBeNull();
  });

  it('does not show tip again after dismissal (30-day cooldown)', () => {
    recordScanAndMaybeShowTip(); // scan 1
    recordScanAndMaybeShowTip(); // scan 2
    const tip = recordScanAndMaybeShowTip(); // scan 3 -- shows tip, marks dismissed
    expect(tip).not.toBeNull();

    // 4th scan -- should not show again
    const tip2 = recordScanAndMaybeShowTip();
    expect(tip2).toBeNull();
  });
});
