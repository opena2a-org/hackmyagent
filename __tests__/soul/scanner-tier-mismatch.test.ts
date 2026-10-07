/**
 * #451 — SOUL-TIER-MISMATCH, the tier twin of SOUL-PROFILE-MISMATCH.
 *
 * A `<!-- soul:tier=… -->` marker is honored as written, so `soul:tier=BASIC`
 * over a body that runs an autonomous loop took Capability Boundaries, Agentic
 * Safety and Human Oversight out of the evaluation and returned 100/100
 * HARDENED. The declared tier is now compared with the tier the file's own
 * words suggest, read without the tier marker and without the lines
 * `harden-soul` writes (its template governs sub-agents and loops, which
 * would otherwise land every hardened file on MULTI-AGENT). A narrower
 * declaration raises a HIGH and the #206 clamp applies; an equal or wider one
 * raises nothing.
 */
import { describe, it, expect } from 'vitest';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SoulScanner } from '../../src/soul/scanner';
import { tempDir } from '../helpers/temp-dir';

const scanner = new SoulScanner();

function tmpDirWithSoul(content: string): string {
  const dir = tempDir('tier-mismatch-');
  writeFileSync(join(dir, 'SOUL.md'), content, 'utf-8');
  return dir;
}

/** A body with no tool, agentic or multi-agent keyword, hardened by harden-soul. */
async function hardenedBasic(): Promise<string> {
  const dir = tmpDirWithSoul('# Support bot\n\nThe agent answers questions about our documentation.\n');
  await scanner.hardenSoul(dir);
  return dir;
}

describe('SOUL-TIER-MISMATCH (#451)', () => {
  it('harden-soul output at BASIC raises no mismatch: its own template text is not a tier signal', async () => {
    const dir = await hardenedBasic();
    expect(readFileSync(join(dir, 'SOUL.md'), 'utf-8')).toContain('<!-- soul:tier=BASIC -->');

    const result = await scanner.scanSoul(dir);
    expect(result.agentTier).toBe('BASIC');
    expect(result.tierMismatch).toBeUndefined();
    expect(result.score).toBe(100);
    expect(result.domains.filter((d) => d.skippedByTier).map((d) => d.domain))
      .toEqual(['Capability Boundaries', 'Agentic Safety', 'Human Oversight']);
  });

  it('the same file with an agentic body under soul:tier=BASIC raises HIGH and is not hardened', async () => {
    const dir = await hardenedBasic();
    appendFileSync(join(dir, 'SOUL.md'), '\n## Operation\nThe agent runs an autonomous loop over the ticket queue.\n');

    const result = await scanner.scanSoul(dir);
    expect(result.agentTier).toBe('BASIC');
    expect(result.tierMismatch).toEqual({
      declaredTier: 'BASIC',
      source: 'marker',
      inferredTier: 'AGENTIC',
      hiddenDomains: ['Capability Boundaries', 'Agentic Safety', 'Human Oversight'],
      hiddenControls: 40,
    });
    expect(result.rawScore).toBe(100);
    expect(result.score).toBe(74);
    expect(result.scoreClamped).toBe(true);
    expect(result.conformance).not.toBe('hardened');
    expect(result.level).not.toBe('hardened');
  });

  it('an equal declaration raises nothing', async () => {
    const dir = tmpDirWithSoul('# Helper\n\n<!-- soul:tier=TOOL-USING -->\n\nThe agent calls MCP tools to look up tickets.\n');
    expect((await scanner.scanSoul(dir)).tierMismatch).toBeUndefined();
  });

  it('a wider declaration raises nothing', async () => {
    const dir = tmpDirWithSoul('# Support bot\n\n<!-- soul:tier=MULTI-AGENT -->\n\nThe agent answers questions.\n');
    const result = await scanner.scanSoul(dir);
    expect(result.agentTier).toBe('MULTI-AGENT');
    expect(result.tierMismatch).toBeUndefined();
  });

  it('a detected tier raises nothing: there is no declaration to compare', async () => {
    const dir = tmpDirWithSoul('# Worker\n\nThe agent runs an autonomous loop over the queue.\n');
    const result = await scanner.scanSoul(dir);
    expect(result.agentTier).toBe('AGENTIC');
    expect(result.tierMismatch).toBeUndefined();
  });

  it('a narrower --tier flag raises it with source flag', async () => {
    const dir = tmpDirWithSoul('# Worker\n\nThe agent runs an autonomous loop over the queue.\n');
    const result = await scanner.scanSoul(dir, { tier: 'basic' });
    expect(result.agentTier).toBe('BASIC');
    expect(result.tierMismatch?.source).toBe('flag');
    expect(result.tierMismatch?.declaredTier).toBe('BASIC');
    expect(result.tierMismatch?.inferredTier).toBe('AGENTIC');
  });

  it('a narrower tier that hides no control under the profile raises nothing', async () => {
    // AGENTIC to MULTI-AGENT adds controls only in Trust Hierarchy and
    // Agentic Safety, and the conversational profile evaluates neither.
    const dir = tmpDirWithSoul(
      '# Bot\n\n<!-- soul:tier=AGENTIC -->\n<!-- soul:profile=conversational -->\n\nA coordinator for a swarm of chat helpers.\n',
    );
    const result = await scanner.scanSoul(dir);
    expect(result.agentTier).toBe('AGENTIC');
    expect(result.tierMismatch).toBeUndefined();
  });

  it('a hidden control with no hidden domain is still reported, with an empty domain list', async () => {
    const dir = tmpDirWithSoul('# Lead\n\n<!-- soul:tier=AGENTIC -->\n\nThe agent is the coordinator for a swarm of workers.\n');
    const result = await scanner.scanSoul(dir);
    expect(result.tierMismatch?.inferredTier).toBe('MULTI-AGENT');
    expect(result.tierMismatch?.hiddenDomains).toEqual([]);
    expect(result.tierMismatch?.hiddenControls).toBeGreaterThan(0);
  });
});
