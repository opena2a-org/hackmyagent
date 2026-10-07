/**
 * #451 — scan-soul on the tier path printed `Level HARDENED` at 100/100 while
 * 3 of 9 domains were "not applicable at BASIC tier", with no Scope line. The
 * profile path already qualified its label and named what it skipped; the
 * tier path now does the same, and a tier marker narrower than the body
 * raises SOUL-TIER-MISMATCH.
 *
 * Spawns the built CLI and drives it from `harden-soul` output, the shape the
 * issue was measured on.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

function run(...args: string[]): { stdout: string; stderr: string; status: number | null } {
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
}

function hardened(body: string, ...flags: string[]): string {
  const dir = tempDir('tier-scope-');
  if (body) writeFileSync(join(dir, 'SOUL.md'), body, 'utf-8');
  const r = run('harden-soul', dir, ...flags);
  expect(r.status, `harden-soul failed:\n${r.stderr}`).toBe(0);
  return dir;
}

const levelLine = (out: string) => out.split('\n').find((l) => /^\s*Level\s/.test(l)) ?? '';
const scopeLine = (out: string) => out.split('\n').find((l) => /^\s*Scope\s/.test(l));

const PLAIN_BODY = '# Support bot\n\nThe agent answers questions about our documentation.\n';

beforeAll(assertDistFresh);

describe('scan-soul tier scope (#451)', () => {
  it('BASIC tier: the label carries the tier and counts, and a Scope line names the domains', () => {
    const { stdout } = run('scan-soul', hardened(PLAIN_BODY));
    expect(stdout).toMatch(/100\/100/);
    expect(levelLine(stdout)).toMatch(/Level\s+HARDENED \(BASIC tier — 6 of 9 domains applicable\)/);
    expect(scopeLine(stdout)).toMatch(
      /Scope\s+6\/9 domains evaluated \(not applicable at BASIC tier: Capability Boundaries, Agentic Safety, Human Oversight\)/,
    );
    expect(stdout).toMatch(/\(6 of 9 domains evaluated\)/);
    expect(stdout).toMatch(/scope: 6\/9 domains/);
    expect(stdout).not.toContain('SOUL-TIER-MISMATCH');
  });

  it('agentic body under soul:tier=BASIC: SOUL-TIER-MISMATCH HIGH, and not HARDENED', () => {
    const dir = hardened(PLAIN_BODY);
    appendFileSync(join(dir, 'SOUL.md'), '\n## Operation\nThe agent runs an autonomous loop and calls MCP tools.\n');

    const { stdout } = run('scan-soul', dir);
    expect(stdout).toMatch(/HIGH\s+SOUL-TIER-MISMATCH/);
    expect(stdout).toContain('Declared tier=BASIC via soul:tier marker.');
    expect(stdout).toContain('Body content suggests tier=AGENTIC.');
    expect(stdout).toContain('Capability Boundaries, Agentic Safety, Human Oversight');
    expect(stdout).toContain('Fix: set the marker to <!-- soul:tier=AGENTIC --> or remove it.');
    expect(stdout).toMatch(/score clamped from 100 to 74 -- 1 HIGH unaddressed/);
    expect(levelLine(stdout)).not.toMatch(/HARDENED/);
    expect(levelLine(stdout)).toMatch(/\(BASIC tier — 6 of 9 domains applicable\)/);

    const ci = run('scan-soul', dir, '--ci');
    expect(ci.status).toBe(1);
    expect(ci.stderr).toMatch(/SOUL-TIER-MISMATCH HIGH: declared tier=BASIC .*body suggests tier=AGENTIC/);

    const explained = run('explain', 'SOUL-TIER-MISMATCH');
    expect(explained.status).toBe(0);
    expect(explained.stderr).not.toMatch(/Unknown check ID/i);
    expect(explained.stdout).toMatch(/soul:tier=/);
  });

  it('control: MULTI-AGENT with all 9 domains prints an unqualified label and no Scope line', () => {
    const { stdout } = run('scan-soul', hardened('', '--tier', 'MULTI-AGENT'));
    expect(stdout).toMatch(/MULTI-AGENT tier/);
    expect(levelLine(stdout)).toMatch(/Level\s+HARDENED\s*$/);
    expect(scopeLine(stdout)).toBeUndefined();
    expect(stdout).not.toMatch(/domains evaluated/);
    expect(stdout).not.toContain('SOUL-TIER-MISMATCH');
  });
});
