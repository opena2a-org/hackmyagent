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

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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
  type ContributionEvent,
} from '../../src/telemetry/contribute';
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
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
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
  });

  it('returns a 64-character hex string (SHA-256)', () => {
    const token = getContributorToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is stable across calls (same device, same salt)', () => {
    const token1 = getContributorToken();
    const token2 = getContributorToken();
    expect(token1).toBe(token2);
  });

  it('creates contributor-salt file on first call', () => {
    getContributorToken();
    const saltPath = path.join(tmpHome, 'contributor-salt');
    expect(fs.existsSync(saltPath)).toBe(true);
    const salt = fs.readFileSync(saltPath, 'utf-8').trim();
    expect(salt).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different tokens with different salts', () => {
    const token1 = getContributorToken();

    // Replace the salt
    const saltPath = path.join(tmpHome, 'contributor-salt');
    fs.writeFileSync(saltPath, 'different-salt-value');

    const token2 = getContributorToken();
    expect(token1).not.toBe(token2);
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
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
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
  });

  it('writes events to contribute-queue.json', () => {
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

    const queuePath = path.join(tmpHome, 'contribute-queue.json');
    expect(fs.existsSync(queuePath)).toBe(true);

    const queue = JSON.parse(fs.readFileSync(queuePath, 'utf-8'));
    expect(queue.events).toHaveLength(1);
    expect(queue.events[0].tool).toBe('hackmyagent');
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

    const queuePath = path.join(tmpHome, 'contribute-queue.json');
    const queue = JSON.parse(fs.readFileSync(queuePath, 'utf-8'));
    expect(queue.events).toHaveLength(2);
  });
});

// ---------------------------------------------------------------
// flushQueue (with mocked fetch)
// ---------------------------------------------------------------

describe('flushQueue', () => {
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    vi.unstubAllGlobals();
    cleanupDir(tmpHome);
  });

  it('submits batch to /api/v1/contribute endpoint', async () => {
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
    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://registry.opena2a.org/api/v1/contribute');
    expect(fetchCall[1].method).toBe('POST');

    // Queue should be empty after successful flush
    const queuePath = path.join(tmpHome, 'contribute-queue.json');
    const queue = JSON.parse(fs.readFileSync(queuePath, 'utf-8'));
    expect(queue.events).toHaveLength(0);
  });

  it('uses custom registry URL when provided', async () => {
    const response = { ok: true, json: async () => ({}) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    });

    await flushQueue('https://custom.registry.example.com');

    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://custom.registry.example.com/api/v1/contribute');
  });

  it('keeps events in queue on network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')));

    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    });

    const ok = await flushQueue();
    expect(ok).toBe(false);

    // Events should still be in queue
    const queuePath = path.join(tmpHome, 'contribute-queue.json');
    const queue = JSON.parse(fs.readFileSync(queuePath, 'utf-8'));
    expect(queue.events).toHaveLength(1);
  });

  it('returns true for empty queue', async () => {
    const ok = await flushQueue();
    expect(ok).toBe(true);
  });
});

// ---------------------------------------------------------------
// submitContribution (legacy compat)
// ---------------------------------------------------------------

describe('submitContribution', () => {
  let tmpHome: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpHome = createTempDir();
    originalEnv = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tmpHome;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENA2A_HOME;
    } else {
      process.env.OPENA2A_HOME = originalEnv;
    }
    vi.unstubAllGlobals();
    cleanupDir(tmpHome);
  });

  it('queues event and flushes (legacy compat)', async () => {
    const response = { ok: true, json: async () => ({}) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response));

    const event: ContributionEvent = {
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    };

    const result = await submitContribution(event, 'https://custom.example.com');
    expect(result.success).toBe(true);
  });

  it('handles network errors gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')));

    const event: ContributionEvent = {
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.11.0',
      timestamp: new Date().toISOString(),
    };

    const result = await submitContribution(event);
    expect(result.success).toBe(false);
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
