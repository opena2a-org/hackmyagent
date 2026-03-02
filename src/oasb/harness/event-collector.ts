import type { ARPEvent, EnforcementResult } from '../../arp';

/**
 * Collects ARP events and enforcement results for test assertions.
 * Supports async waiting for specific events with timeout.
 */
export class EventCollector {
  private events: ARPEvent[] = [];
  private enforcements: EnforcementResult[] = [];
  private waiters: Array<{
    predicate: (event: ARPEvent) => boolean;
    resolve: (event: ARPEvent) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  /** Handler to register on ARP's onEvent */
  readonly eventHandler = (event: ARPEvent): void => {
    this.events.push(event);

    // Check if any waiters match
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const waiter = this.waiters[i];
      if (waiter.predicate(event)) {
        clearTimeout(waiter.timer);
        waiter.resolve(event);
        this.waiters.splice(i, 1);
      }
    }
  };

  /** Handler to register on ARP's onEnforcement */
  readonly enforcementHandler = (result: EnforcementResult): void => {
    this.enforcements.push(result);
  };

  /** Wait for an event matching a predicate, with timeout */
  waitForEvent(
    predicate: (event: ARPEvent) => boolean,
    timeoutMs: number = 10000,
  ): Promise<ARPEvent> {
    // Check existing events first
    const existing = this.events.find(predicate);
    if (existing) return Promise.resolve(existing);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waiters.findIndex((w) => w.resolve === resolve);
        if (idx >= 0) this.waiters.splice(idx, 1);
        reject(new Error(`Timed out after ${timeoutMs}ms waiting for event`));
      }, timeoutMs);

      this.waiters.push({ predicate, resolve, timer });
    });
  }

  /** Check if any event matches a predicate */
  hasEvent(predicate: (event: ARPEvent) => boolean): boolean {
    return this.events.some(predicate);
  }

  /** Get all events */
  getEvents(): ARPEvent[] {
    return [...this.events];
  }

  /** Get events by category */
  eventsByCategory(category: string): ARPEvent[] {
    return this.events.filter((e) => e.category === category);
  }

  /** Get events by severity */
  eventsBySeverity(severity: string): ARPEvent[] {
    return this.events.filter((e) => e.severity === severity);
  }

  /** Get events by source */
  eventsBySource(source: string): ARPEvent[] {
    return this.events.filter((e) => e.source === source);
  }

  /** Get all enforcement results */
  getEnforcements(): EnforcementResult[] {
    return [...this.enforcements];
  }

  /** Get enforcement results by action */
  enforcementsByAction(action: string): EnforcementResult[] {
    return this.enforcements.filter((e) => e.action === action);
  }

  /** Reset all collected data */
  reset(): void {
    this.events = [];
    this.enforcements = [];
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timer);
    }
    this.waiters = [];
  }
}
