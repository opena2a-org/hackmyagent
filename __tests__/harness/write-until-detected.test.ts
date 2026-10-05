/**
 * Contract for `writeUntilDetected` (#871), the helper E2E-001 uses so a live
 * filesystem detection does not depend on FSEvents delivering one particular
 * write. The monitor is simulated here: each case decides which writes the
 * "watcher" reports and when, which is the behaviour measured on a loaded
 * macOS machine (writes reported late, or never).
 */
import { describe, it, expect } from 'vitest';
import type { ARPEvent } from '../../src/arp';
import { EventCollector } from '../../src/oasb/harness/event-collector';
import { writeUntilDetected } from '../helpers/write-until-detected';

function fsEvent(file: string): ARPEvent {
  return {
    id: `evt-${file}`,
    timestamp: new Date().toISOString(),
    source: 'filesystem',
    category: 'violation',
    severity: 'high',
    description: `Access to sensitive path: ${file} (change)`,
    data: { path: file, eventType: 'change', sensitive: true },
    classifiedBy: 'L0-rules',
  };
}

const isEnv = (e: ARPEvent): boolean => e.source === 'filesystem' && String(e.data.path) === '.env';

describe('writeUntilDetected', () => {
  it('writes again when the watcher drops a write, and resolves on the first one it reports', async () => {
    const collector = new EventCollector();
    let writes = 0;
    const write = (): void => {
      writes += 1;
      // The first two writes are coalesced away and never reported.
      if (writes === 3) setTimeout(() => collector.eventHandler(fsEvent('.env')), 5);
    };

    const event = await writeUntilDetected(collector, write, isEnv, {
      timeoutMs: 5_000,
      retryEveryMs: 50,
    });

    expect(event.data.path).toBe('.env');
    expect(writes).toBe(3);
  });

  it('accepts an event that arrives after a later write has started', async () => {
    const collector = new EventCollector();
    let writes = 0;
    const write = (): void => {
      writes += 1;
      // Only the first write is reported, two and a half retry intervals late.
      if (writes === 1) setTimeout(() => collector.eventHandler(fsEvent('.env')), 125);
    };

    const event = await writeUntilDetected(collector, write, isEnv, {
      timeoutMs: 5_000,
      retryEveryMs: 50,
    });

    expect(event.data.path).toBe('.env');
    expect(writes).toBeGreaterThanOrEqual(3);
  });

  it('ignores events that do not match the predicate', async () => {
    const collector = new EventCollector();
    let writes = 0;
    const write = (): void => {
      writes += 1;
      collector.eventHandler(fsEvent(writes < 3 ? 'output.json' : '.env'));
    };

    const event = await writeUntilDetected(collector, write, isEnv, {
      timeoutMs: 5_000,
      retryEveryMs: 20,
    });

    expect(event.data.path).toBe('.env');
    expect(writes).toBe(3);
  });

  it('fails after the total budget, naming the number of writes made', async () => {
    const collector = new EventCollector();
    let writes = 0;
    const started = Date.now();

    await expect(
      writeUntilDetected(collector, () => { writes += 1; }, isEnv, {
        timeoutMs: 200,
        retryEveryMs: 50,
      }),
    ).rejects.toThrow(/No matching filesystem event within 200ms across \d+ write\(s\)/);

    expect(Date.now() - started).toBeGreaterThanOrEqual(190);
    expect(writes).toBeGreaterThanOrEqual(2);
  });
});
