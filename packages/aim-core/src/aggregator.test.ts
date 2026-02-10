import { describe, it, expect } from 'vitest';
import { EventAggregator } from './aggregator';
import type { AuditEventInput } from './types';

function makeInput(plugin: string, action: string): AuditEventInput {
  return {
    plugin,
    action,
    target: 'test',
    result: 'allowed',
  };
}

describe('EventAggregator', () => {
  it('aggregates repeated events', () => {
    const aggregator = new EventAggregator(60_000);

    aggregator.add(makeInput('test', 'scan'));
    aggregator.add(makeInput('test', 'scan'));
    aggregator.add(makeInput('test', 'scan'));

    // Flush all — should produce 1 aggregated event with count=3
    const events = aggregator.flushAll();
    expect(events).toHaveLength(1);
    expect(events[0].metadata?.count).toBe(3);
    expect(events[0].metadata?.aggregated).toBe(true);
  });

  it('keeps different events in separate buckets', () => {
    const aggregator = new EventAggregator(60_000);

    aggregator.add(makeInput('plugin-a', 'scan'));
    aggregator.add(makeInput('plugin-b', 'fix'));

    expect(aggregator.getBucketCount()).toBe(2);

    const events = aggregator.flushAll();
    expect(events).toHaveLength(2);
  });

  it('single event has count=1 and aggregated=false', () => {
    const aggregator = new EventAggregator(60_000);

    aggregator.add(makeInput('test', 'single'));

    const events = aggregator.flushAll();
    expect(events).toHaveLength(1);
    expect(events[0].metadata?.count).toBe(1);
    expect(events[0].metadata?.aggregated).toBe(false);
  });

  it('flush expired leaves active buckets', () => {
    // Use a very long window so nothing expires
    const aggregator = new EventAggregator(999_999);

    aggregator.add(makeInput('test', 'active'));

    const expired = aggregator.flushExpired();
    expect(expired).toHaveLength(0);
    expect(aggregator.getBucketCount()).toBe(1);
  });

  it('stop flushes all buckets', () => {
    const aggregator = new EventAggregator(60_000);

    aggregator.add(makeInput('test', 'shutdown'));
    aggregator.add(makeInput('test', 'shutdown'));

    const events = aggregator.stop();
    expect(events).toHaveLength(1);
    expect(events[0].metadata?.count).toBe(2);
    expect(aggregator.getBucketCount()).toBe(0);
  });

  it('calls flush handler when flushing', () => {
    const aggregator = new EventAggregator(60_000);
    const received: unknown[] = [];

    aggregator.setFlushHandler((events) => {
      received.push(...events);
    });

    aggregator.add(makeInput('test', 'handler'));
    aggregator.flushAll();

    expect(received).toHaveLength(1);
  });

  it('groups by plugin+action+target+result', () => {
    const aggregator = new EventAggregator(60_000);

    // Same plugin+action+target but different result
    aggregator.add({ plugin: 'p', action: 'a', target: 't', result: 'allowed' });
    aggregator.add({ plugin: 'p', action: 'a', target: 't', result: 'denied' });

    expect(aggregator.getBucketCount()).toBe(2);
  });
});
