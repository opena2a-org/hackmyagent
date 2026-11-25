/**
 * #1013 — scan-soul missed a profile narrowed by a keyword.
 *
 * With no `soul:profile` marker and no `--profile` flag, `detectProfile`
 * matches its keywords as substrings (`chat`, `assistant`, `code`), so one
 * sentence saying "Users reach it over chat." turned a body that describes
 * shell commands and human sign-off into a `conversational` scan that skips
 * Capability Boundaries and Human Oversight. `profileMismatch` was only
 * computed for a marker or a flag, so nothing said so.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const SOUL = `# Ops Agent

Users reach it over chat.

## Capability Boundaries

Run shell commands within the project directory. Never run destructive commands.

## Human Oversight

Escalate destructive operations to a human before acting.

## Trust Hierarchy

System prompt has highest authority.
`;

let root: string;

beforeAll(() => {
  root = tempDir('hma-1013-');
  fs.writeFileSync(path.join(root, 'SOUL.md'), SOUL);
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]): { out: string; stdout: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { out: `${r.stdout ?? ''}${r.stderr ?? ''}`, stdout: r.stdout ?? '' };
}

describe('#1013 scan-soul reports a keyword-narrowed profile', () => {
  it('RED-ON-BASE: scan-soul --json on a SOUL.md that mentions chat reports profileMismatch', () => {
    const { stdout } = run(['scan-soul', root, '--json']);
    const body = JSON.parse(stdout.slice(stdout.indexOf('{')));
    expect(body.agentProfile).toBe('conversational');
    expect(body.profileMismatch).toBeDefined();
    expect(body.profileMismatch.source).toBe('keywords');
    expect(body.profileMismatch.declaredProfile).toBe('conversational');
    expect(body.profileMismatch.skippedDomains).toContain('Capability Boundaries');
    expect(body.profileMismatch.skippedDomains).toContain('Human Oversight');
  });

  it('the text report says the profile came from a keyword and names a marker that fixes it', () => {
    const { out } = run(['scan-soul', root]);
    expect(out).toContain('SOUL-PROFILE-MISMATCH');
    expect(out).toContain('Detected profile=conversational from a keyword in the text');
    expect(out).not.toContain('via marker or --profile flag');
    expect(out).toMatch(/Fix: add <!-- soul:profile=(?:tool-agent|autonomous) -->/);
  });
});
