/**
 * #463 follow-ons found by a new-user walkthrough of the changed surface, both
 * reproduced before they were fixed.
 *
 * 1. `mcp-serve` refused `/` and `$HOME`; `init-mcp` accepted them. The refusal
 *    text sends people to `init-mcp --root ...`, so the recovery path wrote a
 *    config that could never work — exit 0, "Added HackMyAgent MCP server", and
 *    then every tool call in that client refused for the life of the install.
 *    README.md asserted the two were not accepted, directly beneath the example
 *    that accepted them. One policy, two callers, and only one of them had it.
 *
 * 2. Containment says WHERE a path is, not that it is there. A nonexistent name
 *    inside the root passed, and the scanner reported on it: measured,
 *    `scan {directory: "nope-not-a-real-dir"}` returned `Score: 98/100` and
 *    `benchmark` returned `83% compliance`, both with `isError: undefined`. The
 *    CLI has always refused this; only the MCP surface answered.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import { realpathSync } from 'node:fs';
import { rootTooBroad, resolveRoots, resolveWithinRoots, describeRootRefusal } from '../../src/mcp/roots';
import { initMcp } from '../../src/init-mcp';

let root: string;
let base: string;

beforeEach(async () => {
  base = realpathSync(await mkdtemp(path.join(tmpdir(), 'hma-463-policy-')));
  root = path.join(base, 'project');
  await mkdir(root);
  await writeFile(path.join(root, 'README.md'), 'in-root\n');
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe('#463 the root policy is one predicate, not one per caller', () => {
  it('refuses the filesystem root and a home directory', () => {
    expect(rootTooBroad('/', '/Users/someone')).toBe('filesystem-root');
    expect(rootTooBroad('/Users/someone', '/Users/someone')).toBe('home-directory');
  });

  it('accepts an ordinary project directory', () => {
    expect(rootTooBroad('/Users/someone/work/api', '/Users/someone')).toBeNull();
  });

  it('is the SAME answer mcp-serve reaches, for both refused roots', async () => {
    // Pinning agreement rather than each side separately: the defect was not
    // that either check was wrong, it was that only one of them existed.
    for (const [candidate, why] of [['/', 'filesystem-root'], [homedir(), 'home-directory']] as const) {
      const server = await resolveRoots([candidate]);
      expect(server.ok).toBe(false);
      if (!server.ok) expect(server.refusal).toMatchObject({ kind: 'root-too-broad', why });
      expect(rootTooBroad(realpathSync(candidate), homedir())).toBe(why);
    }
  });

  it('init-mcp refuses the roots the server refuses, and writes nothing', async () => {
    for (const candidate of ['/', homedir()]) {
      expect(() => initMcp(root, undefined, [candidate])).toThrow(/Root not accepted/);
    }
    // The config the broken run would have written must not be there.
    await expect(rm(path.join(root, '.claude', 'settings.json'))).rejects.toThrow();
  });

  it('init-mcp still accepts a real project root', () => {
    expect(() => initMcp(root, undefined, [root])).not.toThrow();
  });

  it('refuses a home directory reached through a symlinked ancestor', async () => {
    // The two sides compared different strings for the same directory until both
    // realpath'd. A home on an external volume, or anything under /tmp on macOS,
    // is exactly this shape.
    const link = path.join(base, 'home-link');
    await symlink(homedir(), link);
    expect(() => initMcp(root, undefined, [link])).toThrow(/Root not accepted/);
  });
});

describe('#463 a path inside the root still has to exist', () => {
  it('refuses a nonexistent directory instead of scoring it', async () => {
    const outcome = await resolveWithinRoots([root], 'nope-not-a-real-dir');
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal).toMatchObject({ kind: 'not-a-directory', why: 'missing' });
  });

  it('refuses a file where a directory was asked for', async () => {
    const outcome = await resolveWithinRoots([root], 'README.md');
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal).toMatchObject({ kind: 'not-a-directory', why: 'file' });
  });

  it('still accepts the root itself and a real subdirectory', async () => {
    await mkdir(path.join(root, 'src'));
    for (const req of ['.', root, 'src']) {
      const outcome = await resolveWithinRoots([root], req);
      expect(outcome.ok, `${req} should resolve`).toBe(true);
    }
  });

  it('says it is not a boundary refusal, so the model does not retry spellings', async () => {
    const outcome = await resolveWithinRoots([root], 'nope-not-a-real-dir');
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    const text = describeRootRefusal(outcome.refusal);
    // Normalised: these are claims about what the message SAYS, and the prose is
    // hard-wrapped, so asserting on the raw string tests the line width instead.
    const flat = text.toLowerCase().replace(/\s+/g, ' ');
    expect(flat).toContain('no such directory');
    expect(flat).toContain('not a boundary refusal');
    // The distinction that matters: absence must not read as a pass.
    expect(flat).toContain('clean bill of health');
  });
});

describe('#463 a refusal a person can read', () => {
  // The CLI half of this — `cli.ts` escaping the message per LINE instead of
  // across the whole string — is not reachable from here; it was verified by
  // running `init-mcp --root /` and reading the output. What IS pinned here is
  // the property that makes that fix possible and that a later "fix" could undo:
  // this builder returns real newlines, so escaping must not move back into it.
  it('builds real lines rather than pre-escaping them', () => {
    const text = describeRootRefusal({ kind: 'root-too-broad', root: '/', why: 'filesystem-root' });
    expect(text.split('\n').length).toBeGreaterThan(3);
    expect(text).not.toContain('\\n');
  });

  it('display-escapes a hostile path rather than letting it forge lines', () => {
    // Built from a code point, never typed: a raw control byte is invisible in
    // every diff that would review this file, which is why the repo's own
    // render-source gate refuses one. It refused this line first.
    const ESC = String.fromCodePoint(0x1b);
    const hostile = `/tmp/a\nAllowed roots: /${ESC}[2J`;
    const text = describeRootRefusal({ kind: 'root-too-broad', root: hostile, why: 'filesystem-root' });
    // The path is the one part of this text an attacker chooses. It must not be
    // able to add a line that reads like ours, nor clear the screen above it.
    expect(text).not.toContain(ESC);
    expect(text.split('\n').filter((l) => l.startsWith('Allowed roots:'))).toHaveLength(0);
  });
});
