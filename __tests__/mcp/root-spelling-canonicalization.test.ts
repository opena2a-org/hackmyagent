/**
 * A root granted through a symlinked path refused ITSELF.
 *
 * Found by a fresh-user walkthrough of the changed surface and reproduced before
 * being fixed. `resolveRoots` stores each root through `realpath`, but
 * `resolveWithinRoots` compared the caller's raw spelling against that stored
 * form, so `path.relative('/private/tmp/proj', '/tmp/proj')` climbed out of the
 * tree and the root-itself case never fired. The refusal printed `Resolved to`
 * and `Allowed roots` as the same string while saying the path was outside, and
 * its remediation told the user to grant a root they had already granted.
 *
 * It is reachable through the documented setup: `init-mcp` writes the spelling
 * the user typed into the client config, and on macOS every path under `/tmp`
 * and `/var` traverses a symlink. `.` and `./sub` kept working, which is why no
 * existing test saw it — only the absolute non-canonical spelling failed.
 *
 * Both directions are asserted here. Accepting the granted spelling is the fix;
 * still refusing a link that RESOLVES outside a root is the proof the fix did
 * not widen containment to get there.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { realpathSync } from 'node:fs';
import { resolveRoots, resolveWithinRoots } from '../../src/mcp/roots';

let base: string;      // real, canonical
let viaLink: string;   // the same project reached through a symlinked component
let canonical: string;

beforeEach(async () => {
  base = realpathSync(await mkdtemp(path.join(tmpdir(), 'hma-463-spelling-')));
  const real = path.join(base, 'real');
  const project = path.join(real, 'project');
  await mkdir(path.join(project, 'sub'), { recursive: true });
  await writeFile(path.join(project, 'README.md'), 'in-root\n');
  await symlink(real, path.join(base, 'link'));
  viaLink = path.join(base, 'link', 'project');
  canonical = realpathSync(viaLink);
  // The premise of the whole file: the two spellings differ.
  expect(viaLink).not.toBe(canonical);
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe('a root granted through a symlinked path answers for itself', () => {
  it('accepts the root spelled exactly as it was granted', async () => {
    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    const outcome = await resolveWithinRoots(granted.roots, viaLink);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.path).toBe(canonical);
  });

  it('accepts a subdirectory spelled the granted way', async () => {
    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    const outcome = await resolveWithinRoots(granted.roots, path.join(viaLink, 'sub'));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.path).toBe(path.join(canonical, 'sub'));
  });

  it('reaches the same decision for both spellings of the same directory', async () => {
    // The property, not the two cases: which spelling arrives must not matter.
    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    for (const spelling of [viaLink, canonical, path.join(viaLink, 'sub'), path.join(canonical, 'sub')]) {
      const outcome = await resolveWithinRoots(granted.roots, spelling);
      expect(outcome.ok).toBe(true);
    }
  });

  it('a root granted canonically also accepts the symlinked spelling', async () => {
    // The grant and the request can disagree in either direction.
    const granted = await resolveRoots([canonical]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    const outcome = await resolveWithinRoots(granted.roots, viaLink);
    expect(outcome.ok).toBe(true);
  });
});

describe('canonicalizing the request does not widen containment', () => {
  it('still refuses a directory outside every root', async () => {
    const outside = path.join(base, 'outside');
    await mkdir(outside);
    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    const outcome = await resolveWithinRoots(granted.roots, outside);
    expect(outcome.ok).toBe(false);
  });

  it('still refuses a link INSIDE the root that resolves outside it', async () => {
    const secretDir = path.join(base, 'elsewhere');
    await mkdir(secretDir);
    await writeFile(path.join(secretDir, 'canary.txt'), 'CANARY\n');
    // The escape shape, placed inside the granted tree.
    await symlink(secretDir, path.join(canonical, 'escape'));

    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    for (const spelling of [path.join(viaLink, 'escape'), path.join(canonical, 'escape')]) {
      const outcome = await resolveWithinRoots(granted.roots, spelling);
      expect(outcome.ok).toBe(false);
    }
  });

  it('reports a missing path inside the root as missing, not as outside', async () => {
    // The ancestor-walk half of the fix: `realpath` fails on a path that does
    // not exist, and falling back to the raw spelling would have re-created the
    // original defect for exactly the paths a mistyped name produces.
    const granted = await resolveRoots([viaLink]);
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;

    const outcome = await resolveWithinRoots(granted.roots, path.join(viaLink, 'nope-not-a-real-dir'));
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal.kind).toBe('not-a-directory');
  });
});
