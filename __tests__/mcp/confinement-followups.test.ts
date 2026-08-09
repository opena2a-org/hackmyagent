/**
 * #463 — the properties a scoped re-review found unpinned after the first fix
 * round, plus the two regressions that round introduced.
 *
 * Every one of these survived a mutant or was measured as a live defect. They
 * are here rather than in the main confinement file because each pins a rule the
 * first round asserted in a comment and nothing checked.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { realpathSync, realpathSync as rp } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import { handleToolCall } from '../../src/mcp-server';
import { resolveWithinRoots, rootTooBroad } from '../../src/mcp/roots';
import { initMcp } from '../../src/init-mcp';

let base: string;
let root: string;
let outside: string;

beforeEach(async () => {
  base = realpathSync(await mkdtemp(path.join(tmpdir(), 'hma-463-follow-')));
  root = path.join(base, 'project');
  outside = path.join(base, 'elsewhere');
  await mkdir(root);
  await mkdir(outside);
  await writeFile(path.join(root, 'mcp.json'), '{}\n');
  await writeFile(path.join(outside, 'real.env'), 'AWS_SECRET_ACCESS_KEY=CANARY_FOLLOWUP\nDB_PASSWORD=CANARY_PW\n');
  await symlink(path.join(outside, 'real.env'), path.join(root, '.env'));
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe('#463 the deep_scan result stays machine-readable when it withholds', () => {
  it('returns valid JSON, with the withheld files inside it', async () => {
    // The first round appended a prose note AFTER `JSON.stringify`, so the
    // payload stopped parsing for every client exactly when something was
    // withheld — i.e. precisely in the attack case — while `isError` stayed
    // undefined. A client cannot act on a warning it cannot parse.
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: root }, [root]);
    const text = res.content[0].text;
    const parsed = JSON.parse(text) as { notRead?: Array<{ path: string }>; notReadNotice?: string };
    expect(parsed.notRead?.map((n) => n.path)).toContain('.env');
    expect(parsed.notReadNotice).toBeTruthy();
    expect(text).not.toContain('CANARY_FOLLOWUP');
  });

  it('confines the structural pass too, not only the file bodies', async () => {
    // `deep_scan` makes TWO calls that read the tree — `discoverFiles` for the
    // bodies and `analyze` for the structural findings — and confining one is
    // not confining the class. Mutation caught this: dropping `confine` from the
    // `analyze` call left every other test green, because they assert the secret
    // VALUE is absent and a structural finding carries the key NAME and line
    // number instead. That is still a disclosure about a file outside the root,
    // chosen by an untrusted caller.
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: root }, [root]);
    const text = res.content[0].text;
    const parsed = JSON.parse(text) as { layer2Findings?: unknown[] };
    expect(parsed.layer2Findings).toEqual([]);
    expect(text).not.toContain('AWS_SECRET_ACCESS_KEY');
    expect(text).not.toContain('DB_PASSWORD');
  });

  it('says findings may still reference a file it did not read', async () => {
    // The honesty requirement. Withholding the BYTES is not the same as covering
    // the file, and the earlier notice claimed "nothing below covers them" while
    // structural findings still named it.
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: root }, [root]);
    const notice = (JSON.parse(res.content[0].text) as { notReadNotice: string }).notReadNotice;
    expect(notice.toLowerCase()).toContain('reference');
  });
});

describe('#463 a repeatable --root is actually repeatable', () => {
  it('finds a directory that exists only in the SECOND root', async () => {
    // A mutant-free regression from the first round: the existence check
    // returned its refusal instead of continuing the loop, so a name absent from
    // root A was refused even when root B held it. `--root` is documented
    // repeatable, so this made the documented case unreachable.
    const rootB = path.join(base, 'second');
    await mkdir(path.join(rootB, 'svc'), { recursive: true });
    const outcome = await resolveWithinRoots([root, rootB], 'svc');
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.path).toBe(path.join(rp(rootB), 'svc'));
  });

  it('still refuses a name that is in no root at all', async () => {
    const rootB = path.join(base, 'second');
    await mkdir(rootB, { recursive: true });
    const outcome = await resolveWithinRoots([root, rootB], 'nowhere');
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal.kind).toBe('not-a-directory');
  });
});

describe('#463 one root policy means one ANSWER, not one function', () => {
  it('agrees with mcp-serve on a mixed-case home directory', async (ctx) => {
    // `fs.realpathSync` is case-PRESERVING and `fs.promises.realpath` is
    // case-CANONICALISING. Sharing a predicate while resolving the path two
    // different ways still let init-mcp accept a root mcp-serve refuses, which is
    // the same dead end the shared predicate was introduced to close.
    const home = homedir();
    const mixed = home.replace(/\/([a-z])/, (_m, c: string) => '/' + c.toUpperCase());
    if (mixed === home) return; // no lowercase segment to flip; nothing to prove here

    // The defect only EXISTS on a case-insensitive filesystem, where a mixed-case
    // spelling names the same directory. On a case-sensitive one (Linux CI) the
    // mixed spelling names nothing, `realpath` raises ENOENT, and there is no
    // second spelling for the two resolvers to disagree about. Detect that rather
    // than assume the developer's filesystem: this test previously threw
    // `ENOENT: realpath '/Home/runner'` on ubuntu-latest while passing on macOS.
    let caseInsensitive: boolean;
    try {
      caseInsensitive = realpathSync.native(mixed) === realpathSync.native(home);
    } catch {
      caseInsensitive = false;
    }
    if (!caseInsensitive) {
      // Skip LOUDLY. A bare `return` here would read as a pass on every
      // case-sensitive platform, which is how a policy test stops measuring.
      ctx.skip();
      return;
    }

    // The policy must reach the same verdict however the path is spelled.
    expect(rootTooBroad(realpathSync.native(mixed), realpathSync.native(home))).toBe('home-directory');
    expect(() => initMcp(root, undefined, [mixed])).toThrow(/Root not accepted/);
  });
});
