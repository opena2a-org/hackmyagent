/**
 * QGF-254 — every archive `hma check` unpacks goes through one fence, and that
 * fence refuses an entry that would write outside the destination.
 *
 * Three arms of `check` download an archive whose bytes the target's publisher
 * or its host chooses. Before this module they unpacked it by spawning `tar` or
 * `unzip` inline at seven separate sites, none of which looked at an entry
 * before creating it:
 *
 *   src/cli.ts:13919  tar xzf        checkPyPiPackage
 *   src/cli.ts:13921  unzip -q -o    checkPyPiPackage
 *   src/cli.ts:14156  tar xzf        checkRawUrl
 *   src/cli.ts:14158  tar xjf        checkRawUrl
 *   src/cli.ts:14160  tar xJf        checkRawUrl
 *   src/cli.ts:14162  unzip -q       checkRawUrl
 *   src/cli.ts:14391  tar xzf        checkNpmPackage
 *
 * Each had a `mkdtemp` destination made fresh for the run, which defeats a link
 * the DESTINATION already held and does nothing about one the ARCHIVE plants.
 *
 * What the refusal cases below do NOT assert is anything about `tar(1)` or
 * `unzip(1)`. Whether a host tool follows a link member, strips a leading `..`
 * or refuses an absolute name is a property of the binaries that host happens
 * to ship, and this suite is about a property of this program. Every archive is
 * built by the case that uses it, in its own temporary directory — no crafted
 * archive is a tracked file, because `test-fixtures/` shipped deliberately
 * vulnerable content to every installer once already.
 *
 * Each compression is its own case because `checkRawUrl()` reaches the three
 * through three separate branches selected on a filename suffix and a
 * `content-type` header, both of which the archive's own host chooses. Each
 * carries a benign control, so a refusal can never be a failure to read the
 * container wearing a refusal's clothes.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

import {
  extractArchiveInto,
  ArchiveEntryRefused,
  type ArchiveFormat,
} from '../../src/hardening/extract-archive';
import {
  tarBytes,
  zipBytes,
  bzip2Bytes,
  xzBytes,
  hasXz,
  type TarMember,
  type ZipMember,
} from '../helpers/archive-fixtures';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const MODULE_PATH = 'hardening/extract-archive.ts';

// ---------------------------------------------------------------------------
// QGF-254.AC5 — one fence, and every arm behind it
// ---------------------------------------------------------------------------

/** A spawn whose program is an archiver, in either of the two call shapes. */
const ARCHIVER_SPAWNS: readonly RegExp[] = [
  /\b(?:exec|execSync|execFile|execFileSync|execAsync|spawn|spawnSync)\s*\(\s*['"`](?:tar|unzip|bsdtar)['"`]/,
  /\b(?:exec|execSync|execAsync)\s*\(\s*['"`](?:tar|unzip|bsdtar)\s/,
];

function sourceFilesUnderSrc(): string[] {
  const found: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (/\.(c|m)?tsx?$/.test(entry.name)) found.push(full);
    }
  };
  visit(path.join(REPO_ROOT, 'src'));
  return found.sort();
}

function matchesUnderSrc(expressions: readonly RegExp[]): string[] {
  const hits: string[] = [];
  for (const file of sourceFilesUnderSrc()) {
    const relative = path.relative(path.join(REPO_ROOT, 'src'), file).split(path.sep).join('/');
    fs.readFileSync(file, 'utf8')
      .split('\n')
      .forEach((text, index) => {
        if (!expressions.some((e) => e.test(text))) return;
        hits.push(`${relative}:${index + 1}: ${text.trim()}`);
      });
  }
  return hits;
}

describe('one extraction path, and no archiver spawned beside it', () => {
  it('QGF-254.AC5 no module under src/ spawns tar, unzip or bsdtar', () => {
    const hits = matchesUnderSrc(ARCHIVER_SPAWNS);
    const outside = hits.filter((h) => h.indexOf(MODULE_PATH) !== 0);
    expect(
      outside,
      `an archive is being unpacked by a spawned archiver, outside the fence:\n${outside.join('\n')}`,
    ).toEqual([]);
  });

  it('QGF-254.AC5 the detector sees a spawn that is really there', () => {
    // Vacuity guard: the assertion above is a zero, and a broken expression
    // reports the same zero. These are the seven shapes that WERE in cli.ts.
    const wereThere = [
      "execFileSync('tar', ['xzf', archivePath, '-C', extractDir, '--strip-components=1']);",
      "execFileSync('unzip', ['-q', '-o', archivePath, '-d', extractDir]);",
      "await execAsync('tar', ['xjf', archivePath, '-C', extractDir]);",
      "await execAsync('tar', ['xJf', archivePath, '-C', extractDir]);",
      "await execAsync('unzip', ['-q', archivePath, '-d', extractDir]);",
      'exec(`tar xzf ${archivePath}`);',
      "spawnSync('bsdtar', ['xf', archivePath]);",
    ];
    for (const line of wereThere) {
      expect(ARCHIVER_SPAWNS.some((e) => e.test(line)), `missed: ${line}`).toBe(true);
    }
    // And a remedy string that merely NAMES the tools is not a spawn.
    expect(
      ARCHIVER_SPAWNS.some((e) =>
        e.test('`curl -sL ${url} -o archive && tar tvzf archive (or unzip -l archive)`'),
      ),
    ).toBe(false);
  });

  it('QGF-254.AC5 the fence exports one extraction function, taking an archive path and a destination', () => {
    const source = fs.readFileSync(path.join(REPO_ROOT, 'src', MODULE_PATH), 'utf8');
    const exported = source.match(/^export (?:async )?function (\w+)/gm) ?? [];
    expect(exported.map((e) => e.split(' ').pop())).toEqual([
      'describeArchiveRefusal',
      'extractArchiveInto',
    ]);
    expect(source).toContain(
      'export async function extractArchiveInto(\n  archivePath: string,\n  destDir: string,',
    );
    expect(typeof extractArchiveInto).toBe('function');
  });

  it('QGF-254.AC5 each of the three check arms that unpacks an archive routes through it', () => {
    const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf8').split('\n');
    const bodyOf = (name: string): string[] => {
      const start = cli.findIndex((l) => new RegExp(`^(?:async )?function ${name}\\(`).test(l));
      expect(start, `${name}() is gone from cli.ts`).toBeGreaterThan(-1);
      let end = cli.length;
      for (let i = start + 1; i < cli.length; i++) {
        if (/^(?:async )?function \w+\(/.test(cli[i])) {
          end = i;
          break;
        }
      }
      return cli.slice(start, end);
    };
    for (const arm of ['checkPyPiPackage', 'checkRawUrl', 'checkNpmPackage']) {
      expect(
        bodyOf(arm).some((l) => l.indexOf('extractArchiveInto(') !== -1),
        `${arm}() no longer unpacks through the fence`,
      ).toBe(true);
    }
    // And nothing else under src/ calls it: three arms, three call sites.
    const callers = matchesUnderSrc([/\bextractArchiveInto\s*\(/]).filter(
      (h) => h.indexOf(MODULE_PATH) !== 0,
    );
    expect(callers.map((h) => h.split(':')[0])).toEqual(['cli.ts', 'cli.ts', 'cli.ts']);
  });
});

// ---------------------------------------------------------------------------
// QGF-254.AC6 / QGF-254.AC7 — the refusals
// ---------------------------------------------------------------------------

const GUARDED = Buffer.from('outside the destination, and unchanged by any of this\n');
const PLANTED = Buffer.from('written by an entry the fence should have refused\n');
const BENIGN = Buffer.from('an ordinary member of an ordinary package\n');

interface Bench {
  root: string;
  dest: string;
  outside: string;
  guarded: string;
}

const benches: string[] = [];
afterAll(() => {
  for (const root of benches) fs.rmSync(root, { recursive: true, force: true });
});

function bench(): Bench {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qgf254-extract-fence-'));
  benches.push(root);
  const dest = path.join(root, 'dest');
  const outside = path.join(root, 'outside');
  fs.mkdirSync(dest);
  fs.mkdirSync(outside);
  const guarded = path.join(outside, 'keepme');
  fs.writeFileSync(guarded, GUARDED);
  return { root, dest, outside, guarded };
}

/** Every path named `planted` anywhere under the bench but the destination. */
function plantedOutside(b: Bench): string[] {
  const found: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (full === b.dest) continue;
      if (entry.isDirectory()) visit(full);
      else if (entry.name === 'planted') found.push(full);
    }
  };
  visit(b.root);
  return found;
}

type EscapeClass = 'symlink' | 'parent' | 'absolute' | 'hardlink';

/**
 * What each class must appear in the refusal as. The link classes name the
 * target too: an entry name alone does not tell a reader whether they are
 * looking at a hostile archive or a mis-packed one.
 */
function namedInRefusal(kind: EscapeClass, b: Bench): string[] {
  switch (kind) {
    case 'symlink':
      return ['refused entry "esc"', b.outside];
    case 'parent':
      return ['refused entry "../planted"'];
    case 'absolute':
      return [`refused entry "${path.posix.join(b.outside, 'planted')}"`];
    case 'hardlink':
      return ['refused entry "esc"', '../outside/keepme'];
  }
}

function tarMembers(kind: EscapeClass, b: Bench): TarMember[] {
  switch (kind) {
    case 'symlink':
      // A link out of the destination, then a member written THROUGH it.
      return [
        { name: 'esc', kind: 'symlink', linkTarget: b.outside },
        { name: 'esc/planted', kind: 'file', data: PLANTED },
      ];
    case 'parent':
      return [{ name: '../planted', kind: 'file', data: PLANTED }];
    case 'absolute':
      // Rooted at the bench rather than at `/`: an unprivileged process cannot
      // write `/planted` anyway, so a name it COULD write is the only spelling
      // under which "nothing landed outside" can fail if the fence is removed.
      return [{ name: path.posix.join(b.outside, 'planted'), kind: 'file', data: PLANTED }];
    case 'hardlink':
      // A hard link to a file outside, then a regular member of the same name
      // that would be written through it.
      return [
        { name: 'esc', kind: 'hardlink', linkTarget: '../outside/keepme' },
        { name: 'esc', kind: 'file', data: PLANTED },
      ];
  }
}

function zipMembers(kind: Exclude<EscapeClass, 'hardlink'>, b: Bench): ZipMember[] {
  switch (kind) {
    case 'symlink':
      return [
        { name: 'esc', kind: 'symlink', data: Buffer.from(b.outside) },
        { name: 'esc/planted', kind: 'file', data: PLANTED },
      ];
    case 'parent':
      return [{ name: '../planted', kind: 'file', data: PLANTED }];
    case 'absolute':
      return [{ name: path.posix.join(b.outside, 'planted'), kind: 'file', data: PLANTED }];
  }
}

function writeArchive(b: Bench, name: string, bytes: Buffer): string {
  const at = path.join(b.root, name);
  fs.writeFileSync(at, bytes);
  return at;
}

async function expectRefusal(
  archive: string,
  b: Bench,
  format: ArchiveFormat,
  expected: string[],
): Promise<void> {
  let thrown: unknown;
  try {
    await extractArchiveInto(archive, b.dest, { format });
  } catch (err) {
    thrown = err;
  }
  expect(thrown, 'the archive was not refused').toBeInstanceOf(ArchiveEntryRefused);
  const message = (thrown as Error).message;
  for (const fragment of expected) {
    expect(message, `the refusal does not name ${fragment}`).toContain(fragment);
  }

  expect(plantedOutside(b), 'an entry landed outside the destination').toEqual([]);
  expect(fs.readdirSync(b.dest), 'the destination was partly written before the refusal').toEqual([]);
  expect(fs.readFileSync(b.guarded), 'the file outside the destination changed').toEqual(GUARDED);
}

interface Compression {
  label: string;
  format: ArchiveFormat;
  extension: string;
  compress: (raw: Buffer) => Buffer;
  available: boolean;
}

const COMPRESSIONS: Compression[] = [
  { label: 'tar.gz', format: 'tar.gz', extension: '.tar.gz', compress: (b) => zlib.gzipSync(b), available: true },
  { label: 'tar.bz2', format: 'tar.bz2', extension: '.tar.bz2', compress: bzip2Bytes, available: true },
  // The one container with no Node-side codec. Absent `xz(1)` these four
  // cases say so instead of failing, the same runtime-probe shape the matrix
  // already uses for the two platform-narrowed suites.
  { label: 'tar.xz', format: 'tar.xz', extension: '.tar.xz', compress: xzBytes, available: hasXz() },
];

const TAR_CLASSES: Array<{ kind: EscapeClass; what: string }> = [
  { kind: 'symlink', what: 'a symbolic-link member and the member written through it' },
  { kind: 'parent', what: 'a member whose name climbs out of the destination' },
  { kind: 'absolute', what: 'a member whose name is absolute' },
  { kind: 'hardlink', what: 'a hard-link member to a file outside, and the member that would overwrite it' },
];

describe('a zip cannot write outside its destination, whatever the entry class', () => {
  it('QGF-254.AC6 a zip of ordinary members extracts, so a refusal below is a refusal', () => {
    const b = bench();
    const archive = writeArchive(
      b,
      'benign.zip',
      zipBytes([
        { name: 'pkg/', kind: 'directory', data: Buffer.alloc(0) },
        { name: 'pkg/index.js', kind: 'file', data: BENIGN },
        { name: 'pkg/inside-link', kind: 'symlink', data: Buffer.from('index.js') },
      ]),
    );
    return extractArchiveInto(archive, b.dest, { format: 'zip' }).then((written) => {
      expect(written).toEqual(['pkg', 'pkg/index.js', 'pkg/inside-link']);
      expect(fs.readFileSync(path.join(b.dest, 'pkg', 'index.js'))).toEqual(BENIGN);
      expect(fs.readlinkSync(path.join(b.dest, 'pkg', 'inside-link'))).toBe('index.js');
    });
  });

  for (const kind of ['symlink', 'parent', 'absolute'] as const) {
    const what = TAR_CLASSES.find((c) => c.kind === kind)!.what;
    it(`QGF-254.AC6 zip: ${what} is refused by name, and nothing lands outside`, async () => {
      const b = bench();
      const archive = writeArchive(b, 'hostile.zip', zipBytes(zipMembers(kind, b)));
      await expectRefusal(archive, b, 'zip', namedInRefusal(kind, b));
    });
  }
});

for (const compression of COMPRESSIONS) {
  const suite = compression.available ? describe : describe.skip;
  suite(`a ${compression.label} cannot write outside its destination, whatever the entry class`, () => {
    it(`QGF-254.AC7 ${compression.label}: an archive of ordinary members extracts, so a refusal below is a refusal`, async () => {
      const b = bench();
      const archive = writeArchive(
        b,
        `benign${compression.extension}`,
        compression.compress(
          tarBytes([
            { name: 'pkg/', kind: 'directory' },
            { name: 'pkg/index.js', kind: 'file', data: BENIGN },
            { name: 'pkg/inside-link', kind: 'symlink', linkTarget: 'index.js' },
          ]),
        ),
      );
      const written = await extractArchiveInto(archive, b.dest, { format: compression.format });
      expect(written).toEqual(['pkg', 'pkg/index.js', 'pkg/inside-link']);
      expect(fs.readFileSync(path.join(b.dest, 'pkg', 'index.js'))).toEqual(BENIGN);
      expect(fs.readlinkSync(path.join(b.dest, 'pkg', 'inside-link'))).toBe('index.js');
    });

    for (const entryClass of TAR_CLASSES) {
      it(`QGF-254.AC7 ${compression.label}: ${entryClass.what} is refused by name, and nothing lands outside`, async () => {
        const b = bench();
        const archive = writeArchive(
          b,
          `hostile${compression.extension}`,
          compression.compress(tarBytes(tarMembers(entryClass.kind, b))),
        );
        await expectRefusal(archive, b, compression.format, namedInRefusal(entryClass.kind, b));
      });
    }
  });
}
