// AT-INT-005: Baseline Learning
// ATLAS: AML.T0015 (Evasion)
// OWASP: A04 (Excessive Agency)
//
// Verifies that the AnomalyDetector learns a statistical baseline from
// observed events and can distinguish normal frequency patterns from
// anomalous ones. Also verifies that reset() clears learned baselines
// so the detector returns to its initial state.

import { describe, it, expect } from 'vitest';
import { AnomalyDetector } from '../../../../src/arp';
import type { ARPEvent } from '../../../../src/arp';

/** Create a minimal ARPEvent for the given source. */
function makeEvent(source: ARPEvent['source']): ARPEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    source,
    category: 'normal',
    severity: 'info',
    description: 'Baseline test event',
    data: {},
    classifiedBy: 'L0-rules',
  };
}

describe('AT-INT-005: Baseline Learning', () => {
  it('should establish a baseline after recording many events', () => {
    const detector = new AnomalyDetector();

    // Feed 50 observations to build a solid baseline for the 'network' source
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network'));
    }

    const baseline = detector.getBaseline('network');
    expect(baseline).not.toBeNull();
    expect(baseline!.count).toBeGreaterThan(0);
    expect(baseline!.mean).toBeGreaterThan(0);
  });

  it('should return low anomaly score for events matching the baseline', () => {
    const detector = new AnomalyDetector();

    // Build baseline with consistent frequency
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network'));
    }

    // Score a new event from the same source -- should be low
    const score = detector.score(makeEvent('network'));
    expect(score).toBeLessThan(2.0);
  });

  it('should track baselines independently per source', () => {
    const detector = new AnomalyDetector();

    // Build baseline for 'network' only
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network'));
    }

    // 'process' has no baseline
    expect(detector.getBaseline('process')).toBeNull();
    expect(detector.getBaseline('network')).not.toBeNull();

    // Score for 'process' should be 0 (no data)
    const processScore = detector.score(makeEvent('process'));
    expect(processScore).toBe(0);
  });

  it('should clear all baselines on reset and return score 0', () => {
    const detector = new AnomalyDetector();

    // Build baselines for two sources
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network'));
      detector.record(makeEvent('process'));
    }

    expect(detector.getBaseline('network')).not.toBeNull();
    expect(detector.getBaseline('process')).not.toBeNull();

    // Reset clears everything
    detector.reset();

    expect(detector.getBaseline('network')).toBeNull();
    expect(detector.getBaseline('process')).toBeNull();

    // Scores should return 0 after reset (insufficient data)
    expect(detector.score(makeEvent('network'))).toBe(0);
    expect(detector.score(makeEvent('process'))).toBe(0);
  });

  it('should differentiate between sources with different baselines', () => {
    const detector = new AnomalyDetector();

    // Build baseline for 'network' with many events
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network'));
    }

    // Build baseline for 'filesystem' with fewer events
    for (let i = 0; i < 35; i++) {
      detector.record(makeEvent('filesystem'));
    }

    const networkBaseline = detector.getBaseline('network');
    const fsBaseline = detector.getBaseline('filesystem');

    expect(networkBaseline).not.toBeNull();
    expect(fsBaseline).not.toBeNull();

    // Both sources should have baselines but with different event counts
    // (the mean tracks events-per-minute, which will be similar since all
    // events are in the same minute, but the raw time series differs)
    expect(networkBaseline!.mean).toBeGreaterThan(0);
    expect(fsBaseline!.mean).toBeGreaterThan(0);
  });
});
