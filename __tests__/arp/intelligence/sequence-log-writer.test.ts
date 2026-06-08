import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import {
  SequenceLogWriter,
  arpEventToLoggedAction,
  type SequenceLogContext,
} from '../../../src/arp/intelligence/sequence-log-writer';
import { projectSequencesFromFile } from '../../../src/arp/intelligence/sequence-projector';
import type { ARPEvent } from '../../../src/arp/types';

/**
 * Coverage for the detection-mode tee that turns live ARP events into the
 * on-disk records the SequenceProjector reads (detection-mode capture).
 */

function event(overrides: Partial<ARPEvent> = {}): ARPEvent {
  return {
    id: 'e',
    timestamp: '2026-06-08T00:00:01.000Z',
    source: 'prompt',
    category: 'normal',
    severity: 'info',
    description: 'd',
    data: {},
    classifiedBy: 'L0-rules',
    ...overrides,
  };
}

function ctx(): SequenceLogContext {
  return { agentId: 'a', sessionId: 's', seq: 1, lastWallClock: 0 };
}

describe('arpEventToLoggedAction', () => {
  it('maps a network egress event to EXTERNAL_CALL with a hashed host and volume', () => {
    const rec = arpEventToLoggedAction(
      event({
        category: 'normal',
        severity: 'info',
        data: { source: 'network', host: 'evil.example.com', responseSize: 2048, capability: 'data:export' },
      }),
      ctx(),
    );
    expect(rec.eventType).toBe('EXTERNAL_CALL');
    expect(rec.capability).toBe('data:export');
    expect(rec.l0Decision).toBe('allow');
    expect(rec.volumeBytes).toBe(2048);
    // host is hashed (64 hex), not stored in the clear
    expect(rec.egressTargetHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rec)).not.toContain('evil.example.com');
  });

  it('carries a cleared classification through when present on the event', () => {
    const rec = arpEventToLoggedAction(
      event({ data: { classification: 'network-egress', source: 'network' } }),
      ctx(),
    );
    expect(rec.classification).toBe('network-egress');
  });

  it('derives a non-allow l0Decision for flagged events', () => {
    expect(arpEventToLoggedAction(event({ category: 'threat' }), ctx()).l0Decision).toBe('alert');
    expect(
      arpEventToLoggedAction(event({ data: { _initialAction: 'kill' } }), ctx()).l0Decision,
    ).toBe('block');
  });

  it('advances the sequence number and inter-event delta in the context', () => {
    const c = ctx();
    const r1 = arpEventToLoggedAction(event({ timestamp: '2026-06-08T00:00:01.000Z' }), c);
    const r2 = arpEventToLoggedAction(event({ timestamp: '2026-06-08T00:00:03.500Z' }), c);
    expect(r1.sequenceNum).toBe(1);
    expect(r2.sequenceNum).toBe(2);
    expect(r1.timestampDelta).toBe(0); // first event has no prior
    expect(r2.timestampDelta).toBe(2500);
  });
});

describe('SequenceLogWriter end-to-end with the projector', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seq-writer-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('appended records project back into an in-scope action sequence', async () => {
    const logPath = path.join(tmpDir, 'sequence-events.jsonl');
    const writer = new SequenceLogWriter(logPath, 'agent-x', 'sess-x');

    writer.append(event({ data: { source: 'filesystem', capability: 'data:read', responseSize: 100 } }));
    writer.append(
      event({ data: { source: 'network', capability: 'data:export', host: 'sink.example', responseSize: 100 } }),
    );

    const seqs = await projectSequencesFromFile(logPath, { grantedScope: new Set(['*']) });
    expect(seqs).toHaveLength(1);
    expect(seqs[0].agentId).toBe('agent-x');
    expect(seqs[0].sessionId).toBe('sess-x');
    expect(seqs[0].actions.map((a) => a.capability)).toEqual(['data:read', 'data:export']);
    // The egress action (a sink) records the prior read as a taint source.
    const egress = seqs[0].actions[1];
    expect(egress.taintSourceSeqs).toEqual([1]);
  });
});
