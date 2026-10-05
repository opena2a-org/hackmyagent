/**
 * The integrity event log is written on every CLI start and every NanoMind
 * scan. It must stay bounded on disk, and an append must read only the end
 * of the file: a long-lived log reached 100+ MB and every append re-parsed
 * all of it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EventChain, sha256, type TamperEvent } from '../../src/nanomind-core/security/integrity-verifier';

const GENESIS = '0'.repeat(64);

function writeChain(path: string, count: number, detail = 'All 4 checks passed (1.00ms)'): TamperEvent {
  let prevHash = GENESIS;
  let last: TamperEvent | null = null;
  const lines: string[] = [];
  for (let seq = 0; seq < count; seq++) {
    last = { seq, timestamp: '2026-01-01T00:00:00.000Z', eventType: 'check_pass', detail, prevHash };
    const line = JSON.stringify(last);
    lines.push(line);
    prevHash = sha256(line);
  }
  writeFileSync(path, lines.join('\n') + '\n');
  return last as TamperEvent;
}

describe('integrity event log bounds', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'hma-event-log-'));
    path = join(dir, 'events.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('links an append to the last event without parsing the lines before it', () => {
    const last: TamperEvent = {
      seq: 41, timestamp: '2026-01-01T00:00:00.000Z', eventType: 'check_pass', detail: 'tail', prevHash: GENESIS,
    };
    // Earlier lines that are not JSON: a whole-file parse throws on them.
    writeFileSync(path, 'not json\n'.repeat(50_000) + JSON.stringify(last) + '\n');

    const event = new EventChain(path, { maxBytes: 64 * 1024 * 1024 }).append('check_pass', 'next');

    expect(event.seq).toBe(42);
    expect(event.prevHash).toBe(sha256(JSON.stringify(last)));
  });

  it('finds a last line longer than one read window, including multi-byte text', () => {
    const chain = new EventChain(path);
    chain.append('startup', 'boot');
    const long = chain.append('check_pass', 'é'.repeat(9_000) + ' end');

    expect(chain.getLastEvent()).toEqual(long);
    const next = chain.append('check_pass', 'after');
    expect(next.seq).toBe(2);
    expect(next.prevHash).toBe(sha256(JSON.stringify(long)));
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
  });

  it('keeps the live log under the cap and one rotated segment, each verifiable', () => {
    const maxBytes = 2048;
    const chain = new EventChain(path, { maxBytes });

    for (let i = 0; i < 200; i++) {
      chain.append('check_pass', `run ${i}`);
      expect(statSync(path).size).toBeLessThanOrEqual(maxBytes);
    }

    expect(readdirSync(dir).sort()).toEqual(['events.jsonl', 'events.jsonl.1']);
    expect(statSync(chain.rotatedPath).size).toBeLessThanOrEqual(maxBytes);

    const live = chain.readAll();
    expect(live[0].seq).toBe(0);
    expect(live[0].prevHash).toBe(GENESIS);
    expect(live[live.length - 1].detail).toBe('run 199');
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
    expect(new EventChain(chain.rotatedPath).verify()).toEqual({ valid: true, brokenAt: -1 });
  });

  it('drops a log already far past the cap instead of keeping it as the rotated segment', () => {
    const maxBytes = 4096;
    writeChain(path, 500);
    expect(statSync(path).size).toBeGreaterThan(maxBytes * 2);

    const chain = new EventChain(path, { maxBytes });
    const event = chain.append('check_pass', 'first run after upgrade');

    expect(existsSync(chain.rotatedPath)).toBe(false);
    expect(event.seq).toBe(0);
    expect(event.prevHash).toBe(GENESIS);
    expect(readFileSync(path, 'utf-8').trim().split('\n')).toHaveLength(1);
  });

  it('rotates a log just over the cap into the rotated segment, intact', () => {
    const before = writeChain(path, 25);
    // A cap equal to the current size: the next line crosses it.
    const chain = new EventChain(path, { maxBytes: statSync(path).size });
    chain.append('check_pass', 'rotates');

    const rotated = new EventChain(chain.rotatedPath);
    expect(rotated.getLastEvent()).toEqual(before);
    expect(rotated.verify()).toEqual({ valid: true, brokenAt: -1 });
    expect(chain.readAll().map(e => e.seq)).toEqual([0]);
  });

  it('appends to the live log, linked and without throwing, when the rotation fails', () => {
    const before = writeChain(path, 25);
    const maxBytes = statSync(path).size;
    const chain = new EventChain(path, { maxBytes });
    // A non-empty directory at <log>.1: rename() cannot replace it.
    mkdirSync(chain.rotatedPath);
    writeFileSync(join(chain.rotatedPath, 'keep'), 'x');

    let event: TamperEvent | undefined;
    expect(() => { event = chain.append('check_pass', 'rotation failed'); }).not.toThrow();

    expect(event?.seq).toBe(before.seq + 1);
    expect(event?.prevHash).toBe(sha256(JSON.stringify(before)));
    expect(chain.getLastEvent()).toEqual(event);
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
    expect(readdirSync(chain.rotatedPath)).toEqual(['keep']);
    // The next append links on as well; the log grows past the cap rather than losing events.
    expect(chain.append('check_pass', 'still failing').seq).toBe(before.seq + 2);
    expect(statSync(path).size).toBeGreaterThan(maxBytes);
  });
});
