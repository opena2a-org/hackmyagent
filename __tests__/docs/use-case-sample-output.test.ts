/**
 * #441 — the use-case guides show output the current tool prints.
 *
 * Three guides opened their sample output with `HackMyAgent v0.10.1 --
 * Security Scanner`, a banner the CLI had not printed in sixteen releases, and
 * under it finding lists, check counts and fix results no build produced. The
 * guides were regenerated against the build; this suite keeps the two things
 * that drifted from coming back unnoticed:
 *
 * - the retired banner, anywhere in docs/ (the CLI prints no such line, which
 *   the second test pins so this one cannot pass vacuously), and
 * - the payload counts red-team-mcp.md states, read from the payload registry
 *   rather than carried as literals.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { getPayloads } from '../../src/attack/payloads';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const RETIRED_BANNER = /HackMyAgent v\d+\.\d+\.\d+\s+--\s+Security Scanner/;

function markdownFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...markdownFiles(full));
    else if (entry.endsWith('.md')) out.push(full);
  }
  return out;
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('#441 use-case guides show output the current tool prints', () => {
  it('no doc shows the retired `HackMyAgent vX -- Security Scanner` banner', () => {
    const docs = [...markdownFiles(path.join(REPO_ROOT, 'docs')), path.join(REPO_ROOT, 'README.md')];
    const offenders = docs
      .filter((f) => RETIRED_BANNER.test(readFileSync(f, 'utf8')))
      .map((f) => path.relative(REPO_ROOT, f));
    expect(offenders).toEqual([]);
  });

  it('the CLI source prints no such banner', () => {
    const printers = sourceFiles(path.join(REPO_ROOT, 'src'))
      .filter((f) => /--\s+Security Scanner/.test(readFileSync(f, 'utf8')))
      .map((f) => path.relative(REPO_ROOT, f));
    expect(printers).toEqual([]);
  });

  it('red-team-mcp.md states the payload counts the registry holds', () => {
    const doc = readFileSync(path.join(REPO_ROOT, 'docs', 'use-cases', 'red-team-mcp.md'), 'utf8');
    const active = getPayloads(undefined, 'active').length;
    const aggressive = getPayloads(undefined, 'aggressive').length;
    const mcpActive = getPayloads(['mcp-exploitation'], 'active').length;

    expect(doc).toContain(`${active} at the default \`active\` intensity, ${aggressive} at \`aggressive\``);
    expect(doc).toContain(`all ${aggressive} payloads`);
    expect(doc).toContain(`\`mcp-exploitation\` category sends ${mcpActive} payloads at the default intensity`);
    expect(doc).toContain(`Attacks: ${mcpActive} sent | ${mcpActive} answered`);
  });
});
