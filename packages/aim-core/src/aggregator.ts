import type { AuditEvent, AuditEventInput } from './types';

/**
 * Event aggregator — summarizes repeated events before reporting.
 * Groups events by (plugin, action, target, result) within a time window.
 * Flushes aggregated events when the window closes.
 */
export class EventAggregator {
  private readonly windowMs: number;
  private readonly buckets = new Map<string, AggregationBucket>();
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private onFlush: ((events: AuditEvent[]) => void) | null = null;

  constructor(windowMs: number = 60_000) {
    this.windowMs = windowMs;
  }

  /** Set the flush callback (called with aggregated events) */
  setFlushHandler(handler: (events: AuditEvent[]) => void): void {
    this.onFlush = handler;
  }

  /** Add an event to the aggregator */
  add(event: AuditEventInput): void {
    const key = `${event.plugin}|${event.action}|${event.target}|${event.result}`;
    const now = Date.now();

    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.windowStart > this.windowMs) {
      // Flush old bucket if it exists
      if (bucket) {
        this.flushBucket(key, bucket);
      }

      bucket = {
        windowStart: now,
        count: 0,
        firstEvent: event,
        lastTimestamp: new Date().toISOString(),
      };
      this.buckets.set(key, bucket);
    }

    bucket.count++;
    bucket.lastTimestamp = new Date().toISOString();
  }

  /** Start periodic flushing of expired windows */
  start(): void {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      this.flushExpired();
    }, this.windowMs);
  }

  /** Stop the aggregator and flush all pending buckets */
  stop(): AuditEvent[] {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    return this.flushAll();
  }

  /** Flush all expired buckets */
  flushExpired(): AuditEvent[] {
    const now = Date.now();
    const flushed: AuditEvent[] = [];

    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.windowStart > this.windowMs) {
        const events = this.flushBucket(key, bucket);
        flushed.push(...events);
        this.buckets.delete(key);
      }
    }

    return flushed;
  }

  /** Flush all buckets regardless of expiry */
  flushAll(): AuditEvent[] {
    const flushed: AuditEvent[] = [];

    for (const [key, bucket] of this.buckets.entries()) {
      const events = this.flushBucket(key, bucket);
      flushed.push(...events);
    }

    this.buckets.clear();
    return flushed;
  }

  /** Get current bucket count */
  getBucketCount(): number {
    return this.buckets.size;
  }

  private flushBucket(key: string, bucket: AggregationBucket): AuditEvent[] {
    const event: AuditEvent = {
      timestamp: bucket.lastTimestamp,
      plugin: bucket.firstEvent.plugin,
      action: bucket.firstEvent.action,
      target: bucket.firstEvent.target,
      result: bucket.firstEvent.result,
      metadata: {
        ...bucket.firstEvent.metadata,
        aggregated: bucket.count > 1,
        count: bucket.count,
        windowStartedAt: new Date(bucket.windowStart).toISOString(),
      },
    };

    const events = [event];

    if (this.onFlush) {
      this.onFlush(events);
    }

    return events;
  }
}

interface AggregationBucket {
  windowStart: number;
  count: number;
  firstEvent: AuditEventInput;
  lastTimestamp: string;
}
