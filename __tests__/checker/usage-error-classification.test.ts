/**
 * #350 — the refusal/environmental split the CLI catch sites rely on.
 *
 * A UsageError prints as our own multi-line guidance either way; what
 * `isRefusal` decides is the TELEMETRY ending: a refusal exits dark
 * (registered unsettled site, converted by #525), anything else settles
 * through `exitRecorded(1, 'error')` and is counted. An adversarial round
 * measured check's 10s registry timeout — thrown mid-work when DNS never
 * answers — riding the refusal branch: the day #525 lands, DNS-dead
 * environments would have been counted as user refusals, corrupting the
 * exact bucket the split protects.
 *
 * #285's division: these cells prove the classifier; the catch sites'
 * wiring to it is structural (`if (isRefusal(error))` around each
 * registered dark exit) and is held by the exit-surface ratchet keeping
 * those sites registered, not by a spawn — a real 10s timeout has no
 * deterministic offline trigger.
 */
import { describe, it, expect } from 'vitest';
import { UsageError, usageError, NetworkTimeoutError, networkTimeoutError, isRefusal } from '../../src/checker/errors';

describe('isRefusal (#350)', () => {
  it('a plain usage error is a refusal', () => {
    expect(isRefusal(usageError`bad flag`)).toBe(true);
    expect(isRefusal(new UsageError('bad target'))).toBe(true);
  });

  it('a network timeout is NOT a refusal, even though it renders as usage guidance', () => {
    expect(isRefusal(networkTimeoutError`Timed out verifying (10s)`)).toBe(false);
    expect(isRefusal(new NetworkTimeoutError('timed out'))).toBe(false);
  });

  it('a timeout still IS a UsageError, so the catch sites print it as authored lines', () => {
    // The print branch keys on `instanceof UsageError`; the dark exit keys
    // on `isRefusal`. Both must hold or the timeout loses its multi-line
    // guidance rendering.
    expect(networkTimeoutError`x` instanceof UsageError).toBe(true);
  });

  it('anything that is not a UsageError is not a refusal', () => {
    expect(isRefusal(new Error('crash'))).toBe(false);
    expect(isRefusal(undefined)).toBe(false);
    expect(isRefusal('string')).toBe(false);
  });

  it('the timeout template escapes interpolated values like usageError does', () => {
    // Same trust rule (#324/#334): an embedded newline in an interpolated
    // value cannot become a line boundary in our authored guidance.
    const forged = 'a\nb';
    const e = networkTimeoutError`saw ${forged} here`;
    expect(e.message.split('\n')).toHaveLength(1);
  });
});
