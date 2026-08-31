/**
 * The out-of-tree link guard in the tracked `fs` namespace, driven directly.
 *
 * The end-to-end half (`out-of-tree-link-confinement.test.ts`) proves zero
 * reaches through the built scanner; this half pins the guard's own contract
 * at the seam every scan-path reader goes through: which members refuse,
 * what the refusal looks like, where it is recorded, and what passes.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as realFs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { fs } from '../../src/hardening/tracked-fs';
import { CoverageLedger, withActiveLedger, currentLedger } from '../../src/hardening/coverage-ledger';

let base: string;
let root: string;
let outside: string;
let rootB: string;

beforeAll(() => {
  base = realFs.realpathSync(realFs.mkdtempSync(path.join(os.tmpdir(), 'hma-guard-')));
  root = path.join(base, 'root');
  outside = path.join(base, 'outside');
  rootB = path.join(base, 'root-b');
  realFs.mkdirSync(path.join(root, 'sub'), { recursive: true });
  realFs.mkdirSync(outside, { recursive: true });
  realFs.mkdirSync(rootB, { recursive: true });
  realFs.writeFileSync(path.join(outside, 'secret.txt'), 'OUTSIDE\n');
  realFs.writeFileSync(path.join(rootB, 'shared.txt'), 'ROOT-B\n');
  realFs.writeFileSync(path.join(root, 'plain.txt'), 'PLAIN\n');
  realFs.writeFileSync(path.join(root, 'sub', 'real.txt'), 'REAL\n');
  realFs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'out.txt'));
  realFs.symlinkSync(path.join('sub', 'real.txt'), path.join(root, 'in.txt'));
  realFs.symlinkSync(path.join(base, 'nowhere'), path.join(root, 'dangling.txt'));
  realFs.symlinkSync(outside, path.join(root, 'outdir'));
  realFs.symlinkSync(path.join(rootB, 'shared.txt'), path.join(root, 'to-b.txt'));
  // Reached by `<root>/outdir/../secret.txt` on the kernel's view (outdir -> outside, then ..).
  realFs.writeFileSync(path.join(base, 'secret.txt'), 'TRAVERSAL\n');
});

afterAll(() => {
  realFs.rmSync(base, { recursive: true, force: true });
});

async function underLedger<T>(fn: (ledger: CoverageLedger) => Promise<T>, roots?: string[]): Promise<{ value: T; ledger: CoverageLedger }> {
  const ledger = new CoverageLedger(root);
  if (roots) ledger.setConfineRoots(roots);
  const value = await withActiveLedger(ledger, () => fn(ledger));
  return { value, ledger };
}

async function rejection(p: Promise<unknown>): Promise<NodeJS.ErrnoException> {
  try {
    await p;
  } catch (err) {
    return err as NodeJS.ErrnoException;
  }
  throw new Error('expected a rejection');
}

describe('tracked-fs out-of-tree link guard', () => {
  it('refuses readFile on a link that resolves outside the root, ENOENT-shaped, and records it', async () => {
    const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(path.join(root, 'out.txt'), 'utf-8')));
    expect(err.code).toBe('ENOENT');
    expect(err.errno).toBe(-2);
    expect(err.syscall).toBe('readFile');
    expect(err.path).toBe(path.join(root, 'out.txt'));
    expect(ledger.withheldLinks).toEqual([
      { rel: 'out.txt', resolved: path.join(outside, 'secret.txt'), call: 'readFile' },
    ]);
    // Never an unread input: the refusal is a policy skip, not a lost input.
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it.each(['stat', 'access', 'readdir', 'opendir', 'open'] as const)(
    '%s on an out-of-tree link is refused the same way',
    async (member) => {
      const target = member === 'readdir' || member === 'opendir' ? path.join(root, 'outdir') : path.join(root, 'out.txt');
      const { value: err, ledger } = await underLedger((_l) => rejection((fs[member] as (p: string) => Promise<unknown>)(target)));
      expect(err.code).toBe('ENOENT');
      expect(ledger.withheldLinks.map((w) => w.call)).toEqual([member]);
      expect(ledger.unreadableInputs.count).toBe(0);
    },
  );

  // AC7 — the argument shape is not a bypass.
  it('refuses the Buffer form of the same path', async () => {
    const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(Buffer.from(path.join(root, 'out.txt')))));
    expect(err.code).toBe('ENOENT');
    expect(ledger.withheldLinks).toHaveLength(1);
    expect(ledger.withheldLinks[0].rel).toBe('out.txt');
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('refuses the file-URL form of the same path', async () => {
    const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(pathToFileURL(path.join(root, 'out.txt')))));
    expect(err.code).toBe('ENOENT');
    expect(ledger.withheldLinks).toHaveLength(1);
    expect(ledger.withheldLinks[0].rel).toBe('out.txt');
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('dedupes by rel: access then readFile on one link is one record, the first call', async () => {
    const { ledger } = await underLedger(async (_l) => {
      await rejection(fs.access(path.join(root, 'out.txt')));
      await rejection(fs.readFile(path.join(root, 'out.txt')));
    });
    expect(ledger.withheldLinks).toEqual([
      { rel: 'out.txt', resolved: path.join(outside, 'secret.txt'), call: 'access' },
    ]);
  });

  it('discloses an out-of-tree symlinked dirent on a successful withFileTypes listing without following it', async () => {
    const { value: entries, ledger } = await underLedger((_l) => fs.readdir(root, { withFileTypes: true }));
    expect(entries.map((e) => e.name)).toContain('out.txt');
    // `to-b.txt` is out of tree here: this ledger has the single default root.
    const rels = ledger.withheldLinks.map((w) => w.rel).sort();
    expect(rels).toEqual(['out.txt', 'outdir', 'to-b.txt']);
    expect(ledger.withheldLinks.every((w) => w.call === 'listing')).toBe(true);
  });

  it('does not disclose a symlinked node_modules or .git dirent at listing time, but still refuses a read through it', async () => {
    const link = path.join(root, 'node_modules');
    realFs.symlinkSync(path.join(base, 'outside-modules'), link);
    realFs.mkdirSync(path.join(base, 'outside-modules'), { recursive: true });
    realFs.writeFileSync(path.join(base, 'outside-modules', 'pkg.json'), '{}');
    try {
      const { ledger } = await underLedger((_l) => fs.readdir(root, { withFileTypes: true }));
      expect(ledger.withheldLinks.map((w) => w.rel)).not.toContain('node_modules');
      const { value: err, ledger: ledger2 } = await underLedger((_l) => rejection(fs.readFile(path.join(link, 'pkg.json'), 'utf8')));
      expect(err.code).toBe('ENOENT');
      expect(ledger2.withheldLinks.map((w) => w.rel)).toContain(path.join('node_modules', 'pkg.json'));
    } finally {
      realFs.rmSync(link, { force: true });
      realFs.rmSync(path.join(base, 'outside-modules'), { recursive: true, force: true });
    }
  });

  // No false withhold.
  it('reads an in-tree link, a plain file, and a listing of the root', async () => {
    const { value, ledger } = await underLedger(async (_l) => ({
      inTree: await fs.readFile(path.join(root, 'in.txt'), 'utf-8'),
      plain: await fs.readFile(path.join(root, 'plain.txt'), 'utf-8'),
      listing: await fs.readdir(root),
    }));
    expect(value.inTree).toBe('REAL\n');
    expect(value.plain).toBe('PLAIN\n');
    expect(value.listing).toContain('plain.txt');
    expect(ledger.withheldLinks.filter((w) => w.rel === 'in.txt' || w.rel === 'plain.txt')).toEqual([]);
  });

  it('lets a dangling link fall through to the real ENOENT and records nothing', async () => {
    const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(path.join(root, 'dangling.txt'))));
    expect(err.code).toBe('ENOENT');
    expect(err.message).not.toContain('withheld');
    expect(ledger.withheldLinks).toEqual([]);
  });

  it('permits lstat and readlink on the link itself (parent resolves inside) and passes realpath through', async () => {
    const { value, ledger } = await underLedger(async (_l) => ({
      lstat: (await fs.lstat(path.join(root, 'out.txt'))).isSymbolicLink(),
      readlink: await fs.readlink(path.join(root, 'out.txt')),
      realpath: await fs.realpath(path.join(root, 'out.txt')),
    }));
    expect(value.lstat).toBe(true);
    expect(value.readlink).toBe(path.join(outside, 'secret.txt'));
    expect(value.realpath).toBe(path.join(outside, 'secret.txt'));
    expect(ledger.withheldLinks).toEqual([]);
  });

  it('refuses lstat under a parent that is an out-of-tree directory link', async () => {
    const { value: err, ledger } = await underLedger((_l) => rejection(fs.lstat(path.join(root, 'outdir', 'secret.txt'))));
    expect(err.code).toBe('ENOENT');
    expect(ledger.withheldLinks).toEqual([
      { rel: path.join('outdir', 'secret.txt'), resolved: path.join(outside, 'secret.txt'), call: 'lstat' },
    ]);
  });

  it('leaves paths lexically outside every root alone', async () => {
    const { value, ledger } = await underLedger((_l) => fs.readFile(path.join(outside, 'secret.txt'), 'utf-8'));
    expect(value).toBe('OUTSIDE\n');
    expect(ledger.withheldLinks).toEqual([]);
  });

  it('passes everything through when no ledger is installed', async () => {
    expect(currentLedger()).toBeNull();
    expect(await fs.readFile(path.join(root, 'out.txt'), 'utf-8')).toBe('OUTSIDE\n');
  });

  // The root SET: a link into another granted root is read; the target root is always a member.
  it('reads a link into a second confinement root and still withholds one into an ungranted path', async () => {
    const { value, ledger } = await underLedger(async (_l) => ({
      toB: await fs.readFile(path.join(root, 'to-b.txt'), 'utf-8'),
      out: await rejection(fs.readFile(path.join(root, 'out.txt'))),
      plain: await fs.readFile(path.join(root, 'plain.txt'), 'utf-8'),
    }), [rootB]);
    expect(value.toB).toBe('ROOT-B\n');
    expect(value.out.code).toBe('ENOENT');
    expect(value.plain).toBe('PLAIN\n');
    expect(ledger.withheldLinks.map((w) => w.rel)).toEqual(['out.txt']);
  });

  it('stays inside under a symlinked ancestor and an unresolved tmpdir spelling', async () => {
    // A root named THROUGH a link: everything under it resolves under the real root.
    const alias = path.join(base, 'alias');
    realFs.symlinkSync(root, alias);
    const ledger = new CoverageLedger(alias);
    const value = await withActiveLedger(ledger, () => fs.readFile(path.join(alias, 'in.txt'), 'utf-8'));
    expect(value).toBe('REAL\n');
    expect(ledger.withheldLinks).toEqual([]);

    // `os.tmpdir()` unresolved (`/var/...` on macOS) against a resolved fixture.
    const unresolvedBase = base.replace(realFs.realpathSync(os.tmpdir()), os.tmpdir());
    const ledger2 = new CoverageLedger(path.join(unresolvedBase, 'root'));
    const value2 = await withActiveLedger(ledger2, () => fs.readFile(path.join(unresolvedBase, 'root', 'in.txt'), 'utf-8'));
    expect(value2).toBe('REAL\n');
    expect(ledger2.withheldLinks).toEqual([]);
  });

  // `..` after a link: the kernel applies it where the link lands, `path.resolve` does not.
  describe('traversal through a link is decided on the kernel\'s view', () => {
    const traversal = () => path.join(root, 'outdir') + path.sep + '..' + path.sep + 'secret.txt';

    it('refuses the string form <root>/outdir/../secret.txt', async () => {
      const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(traversal(), 'utf-8')));
      expect(err.code).toBe('ENOENT');
      expect(ledger.withheldLinks).toEqual([
        { rel: 'outdir' + path.sep + '..' + path.sep + 'secret.txt', resolved: path.join(base, 'secret.txt'), call: 'readFile' },
      ]);
    });

    it('refuses the Buffer form', async () => {
      const { value: err, ledger } = await underLedger((_l) => rejection(fs.readFile(Buffer.from(traversal()))));
      expect(err.code).toBe('ENOENT');
      expect(ledger.withheldLinks).toHaveLength(1);
    });

    it('never reads outside through the file-URL form with %2E%2E', async () => {
      // WHATWG URL parsing treats `%2E%2E` as a dot segment and collapses it
      // in the URL itself, so the path handed to the guard is `<root>/secret.txt`
      // (absent). Either way nothing outside is read.
      const url = new URL('outdir/%2E%2E/secret.txt', pathToFileURL(root + path.sep));
      const { value: err } = await underLedger((_l) => rejection(fs.readFile(url, 'utf-8')));
      expect(err.code).toBe('ENOENT');
      let leaked: string | undefined;
      try { leaked = await withActiveLedger(new CoverageLedger(root), () => fs.readFile(url, 'utf-8')); } catch { /* refused or absent */ }
      expect(leaked).toBeUndefined();
    });

    it('refuses readdir of <root>/outdir/.. (would list the parent of the link target)', async () => {
      const { value: err, ledger } = await underLedger((_l) => rejection(fs.readdir(path.join(root, 'outdir') + path.sep + '..')));
      expect(err.code).toBe('ENOENT');
      expect(ledger.withheldLinks[0]?.resolved).toBe(base);
    });

    it('still reads <root>/sub/../plain.txt, a traversal through a real directory', async () => {
      const { value, ledger } = await underLedger((_l) => fs.readFile(path.join(root, 'sub') + path.sep + '..' + path.sep + 'plain.txt', 'utf-8'));
      expect(value).toBe('PLAIN\n');
      expect(ledger.withheldLinks).toEqual([]);
    });
  });

  it('a confinement root of "/" withholds nothing', async () => {
    const { value, ledger } = await underLedger(async (_l) => ({
      plain: await fs.readFile(path.join(root, 'plain.txt'), 'utf-8'),
      out: await fs.readFile(path.join(root, 'out.txt'), 'utf-8'),
    }), [path.parse(root).root]);
    expect(value.plain).toBe('PLAIN\n');
    expect(value.out).toBe('OUTSIDE\n');
    expect(ledger.withheldLinks).toEqual([]);
  });
});
