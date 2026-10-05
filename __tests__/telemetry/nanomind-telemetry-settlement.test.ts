/**
 * #655 — NanoMind classification telemetry flushes behind `secure`'s
 * settlement point, not mid-scan.
 *
 * `orchestrateNanoMind` runs inside the scan, before `secure` settles its
 * exit code, and used to flush the consent-gated classification queue there.
 * A consenting run that later settled EXIT_UNMEASURED (2) had already posted
 * per-artifact records, past the #464 withhold every outcome wire reads.
 *
 * Cells: a consenting withheld run performs no telemetry POST; a consenting
 * measured run still flushes; the queue survives the withheld run.
 *
 * RED-ON-BASE cells fail on the build before the fix; PIN cells pass on both.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Consent is standing for every cell: the defect is what a CONSENTING run
// sends, and without consent the queue never fills.
vi.mock('../../src/telemetry/opt-in', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/telemetry/opt-in')>()),
  isContributeEnabled: () => true,
}));

// The orchestrator's heavy dependencies are replaced so the cells exercise
// only its flush decision. The scan stand-in queues one classification, the
// way the real scanner-bridge does for every artifact it classifies.
vi.mock('../../src/nanomind-core/daemon-lifecycle', () => ({ ensureDaemon: async () => false }));
vi.mock('../../src/nanomind-core/inference/tme-classifier', () => ({
  getTMEClassifier: () => ({ ensureModel: async () => undefined }),
}));
vi.mock('../../src/nanomind-core/inference/security-analyst', () => ({
  isAnalystReady: async () => false,
  runAnalystInference: async () => null,
  classifyArtifactForCoverage: async () => null,
}));
vi.mock('../../src/nanomind-core/scanner-bridge', () => ({
  runNanoMindScan: async () => {
    const t = await import('../../src/telemetry/nanomind-telemetry');
    t.queueClassificationStat('skill', 'artifact body', 'benign', 0.9, 'test-model');
    return {
      mergedFindings: [],
      astFindings: [],
      nanomindAvailable: true,
      compiledArtifacts: 1,
      compileSetTruncated: false,
      semanticFamilyCoverage: { totalFamilies: 0, artifactsCompiled: 1, fullyExamined: 1, partial: [] },
      artifactSummaries: [],
      integrityStatus: 'CLEAN',
      coverageCandidates: [],
    };
  },
}));

import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';
import {
  clearTelemetryQueue,
  getTelemetryQueueSize,
  queueClassificationStat,
  settleNanoMindTelemetry,
} from '../../src/telemetry/nanomind-telemetry';

const ENDPOINT = '/api/v1/nanomind/telemetry';
let fetchMock: ReturnType<typeof vi.fn>;

const telemetryPosts = () =>
  fetchMock.mock.calls.filter(([url]) => String(url).endsWith(ENDPOINT));

// The orchestrator's flush was a fire-and-forget dynamic import; give it
// room to run before asserting that it did not.
const settleAsync = () => new Promise((resolve) => setTimeout(resolve, 100));

beforeEach(() => {
  clearTelemetryQueue();
  fetchMock = vi.fn(async () => new Response(JSON.stringify({ accepted: 1 }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearTelemetryQueue();
});

describe('#655 the scan itself posts no classification telemetry for secure', () => {
  it('RED-ON-BASE: with the flush deferred, the scan posts nothing and the queue holds its records', async () => {
    await orchestrateNanoMind('/nonexistent-655', [], { silent: true, deferTelemetryFlush: true });
    await settleAsync();
    expect(telemetryPosts()).toHaveLength(0);
    expect(getTelemetryQueueSize()).toBe(1);
  });

  it('PIN: without the option (commands that settle no outcome), the scan still flushes after it', async () => {
    await orchestrateNanoMind('/nonexistent-655', [], { silent: true });
    await vi.waitFor(() => expect(telemetryPosts()).toHaveLength(1));
    expect(getTelemetryQueueSize()).toBe(0);
  });
});

describe('#655 the flush at the settlement point follows the outbound decision', () => {
  it('RED-ON-BASE: a withheld run (exit 2) performs no telemetry POST and keeps its queue', async () => {
    queueClassificationStat('skill', 'artifact body', 'benign', 0.9, 'test-model');
    await settleNanoMindTelemetry(false);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(getTelemetryQueueSize()).toBe(1);
  });

  it('RED-ON-BASE: a measured run flushes the queue to the telemetry endpoint', async () => {
    queueClassificationStat('skill', 'artifact body', 'suspicious', 0.6, 'test-model');
    expect(await settleNanoMindTelemetry(true)).toBe(true);
    const posts = telemetryPosts();
    expect(posts).toHaveLength(1);
    const body = JSON.parse(String((posts[0][1] as RequestInit).body));
    expect(body.stats).toHaveLength(1);
    expect(body.stats[0]).toMatchObject({ contentType: 'skill', classification: 'suspicious', verdict: 'warn' });
    expect(getTelemetryQueueSize()).toBe(0);
  });

  it('RED-ON-BASE: the queue survives the withheld run and the next measured run flushes it', async () => {
    await orchestrateNanoMind('/nonexistent-655', [], { silent: true, deferTelemetryFlush: true });
    await settleNanoMindTelemetry(false);
    await orchestrateNanoMind('/nonexistent-655', [], { silent: true, deferTelemetryFlush: true });
    await settleNanoMindTelemetry(true);
    const posts = telemetryPosts();
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String((posts[0][1] as RequestInit).body)).stats).toHaveLength(2);
  });
});

describe('#655 secure wires the deferred flush to its settled outbound decision', () => {
  const cli = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
  const decision = cli.indexOf('const sendOutbound = outboundAllowed(settled);');

  it('RED-ON-BASE: the scan secure runs defers the flush', () => {
    expect(decision).toBeGreaterThan(-1);
    const semanticPass = cli.lastIndexOf('semanticPass: async', decision);
    const call = cli.slice(semanticPass, cli.indexOf('return { findings: nmResult.mergedFindings }', semanticPass));
    expect(call).toContain('orchestrateNanoMind(');
    expect(call).toContain('deferTelemetryFlush: true');
  });

  it('RED-ON-BASE: the flush is gated on the same decision, after it is made', () => {
    expect(cli.indexOf('settleNanoMindTelemetry(sendOutbound)', decision)).toBeGreaterThan(decision);
  });
});
