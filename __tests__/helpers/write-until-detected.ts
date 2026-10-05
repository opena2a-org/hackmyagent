/**
 * Perform a real filesystem write and wait for ARP's FilesystemMonitor to
 * report it, repeating the write until it does (#871).
 *
 * The monitor is `fs.watch(dir, { recursive: true })`. On macOS that is backed
 * by FSEvents, which gives three guarantees fewer than the tests assumed:
 *
 *   - the stream starts asynchronously, so a write made shortly after
 *     `fs.watch` returns can happen before anything is listening;
 *   - delivery is batched by a system-wide daemon, and on a loaded machine a
 *     write was measured arriving 0.2s to 12s after it was made;
 *   - per-file events can be coalesced away entirely. Over three 16-write
 *     runs, 19 of 48 writes never produced an event at all, eight seconds
 *     after the last one.
 *
 * So one write followed by a fixed wait can only be reliable on a quiet
 * machine: E2E-001 timed out in 3 of 5 isolated runs, on a different case
 * each time.
 * Repeating the write until the event arrives keeps the assertion the same
 * (a real write to that path is detected) without depending on the delivery
 * of any single one. On Linux, inotify reports the first write at once, so the
 * loop ends after one pass.
 *
 * An event that arrives late, after a later write has already started, still
 * counts: `waitForEvent` checks events already collected before it waits.
 */
import type { ARPEvent } from '../../src/arp';

export interface EventWaiter {
  waitForEvent(predicate: (event: ARPEvent) => boolean, timeoutMs: number): Promise<ARPEvent>;
}

export interface WriteUntilDetectedOptions {
  /** Total budget across every write. */
  timeoutMs?: number;
  /** How long to wait after each write before writing again. */
  retryEveryMs?: number;
}

export async function writeUntilDetected(
  waiter: EventWaiter,
  write: () => void,
  predicate: (event: ARPEvent) => boolean,
  { timeoutMs = 30_000, retryEveryMs = 1_000 }: WriteUntilDetectedOptions = {},
): Promise<ARPEvent> {
  const deadline = Date.now() + timeoutMs;
  let writes = 0;
  for (;;) {
    write();
    writes += 1;
    const remaining = deadline - Date.now();
    try {
      return await waiter.waitForEvent(predicate, Math.max(1, Math.min(retryEveryMs, remaining)));
    } catch {
      if (Date.now() >= deadline) {
        throw new Error(
          `No matching filesystem event within ${timeoutMs}ms across ${writes} write(s)`,
        );
      }
    }
  }
}
