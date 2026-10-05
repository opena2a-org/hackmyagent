/**
 * #771 — `scan-soul --deep` gave a different score, and sometimes a different
 * conformance level and exit code, on consecutive runs over an unchanged file
 * when ANTHROPIC_API_KEY was set. With the variable unset every series was
 * byte-identical, so the variation came from the hosted coverage tier.
 *
 * That tier asked a one-word YES/NO question and left `temperature` unset, so
 * the API sampled at its default of 1.0: an answer near the boundary came back
 * YES on some runs and NO on others, and a YES is an upgrade that moves the
 * score. The request now pins `temperature: 0`, the API's lowest-variance
 * setting for the answer.
 *
 * The network is stubbed and the key is a placeholder, so this runs offline and
 * sends nothing anywhere.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { SoulScanner } from '../../src/soul/scanner';

// The 225-byte SOUL.md from the #771 report: no keyword-tier upgrades, so
// every applicable control that fails reaches the hosted tier.
const SOUL = [
  '# SOUL.md',
  '',
  '## Identity',
  'You are a documentation assistant for an internal wiki.',
  '',
  '## Constraints',
  '- Never execute shell commands.',
  '- Only read files under docs/.',
  '',
  '## Trust hierarchy',
  'System prompt > operator > user > tool output.',
  '',
].join('\n');

function soulDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-771-'));
  writeFileSync(path.join(dir, 'SOUL.md'), SOUL);
  return dir;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('#771 the hosted deep coverage tier', () => {
  it('asks for the lowest-variance answer on every request', async () => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'placeholder-not-a-key');
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
      bodies.push(JSON.parse(init.body));
      return { json: async () => ({ content: [{ text: 'NO' }] }) };
    }));

    await new SoulScanner().scanSoul(soulDir(), { deepAnalysis: true });

    expect(bodies.length, 'the fixture must send controls to the hosted tier').toBeGreaterThan(0);
    for (const body of bodies) {
      expect(body.temperature).toBe(0);
    }
  });
});
