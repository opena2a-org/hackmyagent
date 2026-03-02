// BL-003: Baseline Persistence Across Restarts
// Documents gap: baselines are NOT persisted
//
// The AnomalyDetector holds all baseline data in memory. When a new instance
// is created (simulating an agent restart), all learned baselines are lost.
// This test verifies and documents this known gap. A production deployment
// would need to serialize baselines to disk or a database to survive restarts.

import { describe, it, expect, beforeEach } from 'vitest';
import { AnomalyDetector } from '../../../src/arp';
import type { ARPEvent } from '../../../src/arp';

/** Helper: create a minimal ARPEvent for a given source */
function makeEvent(source: 'process' | 'network' | 'filesystem', index: number): ARPEvent {
  return {
    id: `bl003-${source}-${index}`,
    timestamp: new Date().toISOString(),
    source,
    category: 'normal',
    severity: 'info',
    description: `Persistence test event ${index} from ${source}`,
    data: { index },
    classifiedBy: 'L0-rules',
  };
}

describe('BL-003: Baseline Persistence Across Restarts', () => {
  let detector: AnomalyDetector;

  beforeEach(() => {
    detector = new AnomalyDetector();
  });

  it('should accumulate baseline data during a session', () => {
    // Feed 50 observations to build baseline
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('process', i));
    }

    const baseline = detector.getBaseline('process');
    expect(baseline).not.toBeNull();
    expect(baseline!.count).toBeGreaterThan(0);
    expect(baseline!.mean).toBeGreaterThan(0);
  });

  it('should lose all baselines when a new detector is created (simulated restart)', () => {
    // Build baseline on first detector
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('process', i));
    }

    const baselineBefore = detector.getBaseline('process');
    expect(baselineBefore).not.toBeNull();

    // Simulate restart: create a new AnomalyDetector instance
    const restartedDetector = new AnomalyDetector();

    // KNOWN GAP: baseline is lost after restart
    const baselineAfter = restartedDetector.getBaseline('process');
    expect(baselineAfter).toBeNull();

    // Score returns 0 on the restarted detector (no baseline data)
    const testEvent = makeEvent('process', 999);
    const scoreAfterRestart = restartedDetector.score(testEvent);
    expect(scoreAfterRestart).toBe(0);

    // Original detector still has its baseline (in-memory only)
    const scoreOriginal = detector.score(testEvent);
    // Even the original returns 0 because it needs 30+ minute buckets,
    // but the baseline object itself still exists
    expect(scoreOriginal).toBe(0);
    expect(detector.getBaseline('process')).not.toBeNull();
  });

  it('should lose baselines for all sources on restart', () => {
    const sources = ['process', 'network', 'filesystem'] as const;

    // Build baselines for all sources
    for (const source of sources) {
      for (let i = 0; i < 20; i++) {
        detector.record(makeEvent(source, i));
      }
    }

    // Verify all baselines exist
    for (const source of sources) {
      expect(detector.getBaseline(source)).not.toBeNull();
    }

    // Simulate restart
    const restartedDetector = new AnomalyDetector();

    // KNOWN GAP: all baselines lost
    for (const source of sources) {
      expect(restartedDetector.getBaseline(source)).toBeNull();
    }
  });

  it('should require full re-learning after restart (cold start problem)', () => {
    // Build baseline
    for (let i = 0; i < 50; i++) {
      detector.record(makeEvent('network', i));
    }

    const originalBaseline = detector.getBaseline('network');
    expect(originalBaseline).not.toBeNull();
    const originalMean = originalBaseline!.mean;

    // Simulate restart
    const restartedDetector = new AnomalyDetector();

    // Feed the same number of events to the restarted detector
    for (let i = 0; i < 50; i++) {
      restartedDetector.record(makeEvent('network', i));
    }

    const rebuiltBaseline = restartedDetector.getBaseline('network');
    expect(rebuiltBaseline).not.toBeNull();

    // The rebuilt baseline should match the original since we fed identical data
    // (all events land in the same minute, so stats should be equivalent)
    expect(rebuiltBaseline!.mean).toBe(originalMean);
    expect(rebuiltBaseline!.count).toBe(originalBaseline!.count);

    // KNOWN GAP DOCUMENTED: In production, the agent would have no anomaly
    // detection capability between restart and baseline re-establishment.
    // During this cold start window (minimum 30 unique minutes of data),
    // all anomaly scores return 0 regardless of actual behavior.
  });
});
