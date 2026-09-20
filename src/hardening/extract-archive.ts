/**
 * One unpacking path for every archive `hma check` fetches.
 *
 * Three arms of `check` download an archive whose bytes the target's publisher
 * or its host chooses — `checkPyPiPackage`, `checkRawUrl`, `checkNpmPackage` —
 * and until this module they unpacked it by spawning `tar` or `unzip` inline,
 * seven times, with no shared helper and no entry inspection anywhere. Each
 * site created a fresh `mkdtemp` destination, which defeats a symbolic link the
 * DESTINATION already held and does nothing about one the ARCHIVE plants: a
 * member `esc` that is a link to `/etc` followed by a member `esc/planted`
 * writes `planted` into `/etc` on a host tool that follows it, and which host
 * tools follow which entry is a property of the machine the scan happens to run
 * on, not of this program.
 *
 * So the fence is ours and it is one fence. The same reasoning as
 * `contain.ts`, whose header says it plainly: two implementations of one
 * containment property is how an asymmetry arises, so there is one. This module
 * is the extraction counterpart — `contain.ts` decides where a path HMA is
 * about to ACT on resolves to, this decides which archive entries HMA is
 * willing to create at all — and it reuses `isPathWithinDirectory` from there
 * rather than restating it.
 *
 * The shape is: read the archive's own entry table first, refuse the whole
 * archive if ANY entry would land outside the destination, and only then write.
 * Refusing up front rather than per entry is deliberate: an archive that
 * carries one escaping member is not an archive that should be half-unpacked,
 * and a half-unpacked tree is then scanned and scored as if it were the
 * package.
 *
 * The entry table is parsed here, in process, rather than read out of
 * `tar -tv` or `unzip -Z`: those formats vary across implementations and
 * locales, and a fence that mis-parses a listing fails open. Extraction is
 * in-process for the same reason, plus two smaller ones — `unzip(1)` is absent
 * from many minimal images (Node's own slim containers included), and a spawned
 * extractor decides on its own what to do with a link entry after we have
 * already decided.
 *
 * Decompression:
 *   - gzip  — `zlib`, which Node ships.
 *   - bzip2 — decoded here. Node ships no bzip2 and `bzip2(1)` is missing from
 *             the same minimal images, which is exactly where `tar xjf` fails
 *             with a confusing message about a lost child process.
 *   - xz    — delegated to `xz(1)`. No decoder ships with Node and writing an
 *             LZMA2 one is out of proportion to this fence; when the binary is
 *             absent the archive is refused rather than guessed at.
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { execFileSync } from 'child_process';
import { isPathWithinDirectory } from './contain';

/** Archive containers `hma check` is willing to open. */
export type ArchiveFormat = 'tar.gz' | 'tar.bz2' | 'tar.xz' | 'zip';

/**
 * Why an entry was refused. One cause per sentence in
 * `describeArchiveRefusal`, kept beside it so a new cause cannot be added
 * without a sentence for the user who has to decide what to do next.
 */
export type ArchiveRefusalCause =
  | 'absolute-name'
  | 'name-escapes-destination'
  | 'link-escapes-destination'
  | 'unsupported-entry-type'
  | 'parent-outside-destination';

/** One sentence per refusal cause, for the reader of a failed `check`. */
export function describeArchiveRefusal(cause: ArchiveRefusalCause): string {
  switch (cause) {
    case 'absolute-name':
      return 'its name is an absolute path, so it names a location the destination does not contain';
    case 'name-escapes-destination':
      return 'its name climbs out of the destination directory';
    case 'link-escapes-destination':
      return 'it is a link whose target is outside the destination directory';
    case 'unsupported-entry-type':
      return 'it is not a file, a directory or a link, and this unpacker creates nothing else';
    case 'parent-outside-destination':
      return 'the directory that would contain it no longer resolves inside the destination directory';
  }
}

/**
 * The refusal. Carries the entry name and, for a link, the target it points
 * at — the two facts a reader needs to tell a hostile archive from a
 * mis-packed one, and the two this class guarantees are in `message`.
 */
export class ArchiveEntryRefused extends Error {
  readonly archiveName: string;
  readonly entryName: string;
  readonly refusal: ArchiveRefusalCause;
  readonly linkTarget?: string;

  constructor(args: {
    archivePath: string;
    entryName: string;
    refusal: ArchiveRefusalCause;
    linkTarget?: string;
  }) {
    const target = args.linkTarget === undefined ? '' : ` -> "${args.linkTarget}"`;
    super(
      `${path.basename(args.archivePath)}: refused entry "${args.entryName}"${target} — ` +
        `${describeArchiveRefusal(args.refusal)}. Nothing was extracted.`,
    );
    this.name = 'ArchiveEntryRefused';
    this.archiveName = path.basename(args.archivePath);
    this.entryName = args.entryName;
    this.refusal = args.refusal;
    if (args.linkTarget !== undefined) this.linkTarget = args.linkTarget;
  }
}

export interface ExtractArchiveOptions {
  /**
   * The container to read. When omitted the archive's own magic bytes decide.
   * A caller that passes one is stating what it EXPECTS; the magic still wins,
   * because the name and the `content-type` that produced the expectation are
   * both chosen by the host serving the archive.
   */
  format?: ArchiveFormat;
  /** Leading path components to drop, as `tar --strip-components` does. */
  stripComponents?: number;
  /** Ceiling on the bytes this call will hold or write. */
  maxBytes?: number;
}

/**
 * 512 MiB. Large enough for every package either registry serves and small
 * enough that a declared-size lie cannot take the process out: the other open
 * advisory on this tree's transitive `adm-zip` edge is a crafted ZIP that
 * triggers a 4 GB allocation, and an unpacker with no ceiling is that same
 * shape written first-party.
 */
const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;

const TAR_BLOCK = 512;

interface ArchiveEntry {
  /** The name exactly as the archive records it. Never used as a path. */
  name: string;
  kind: 'file' | 'directory' | 'symlink' | 'hardlink' | 'other';
  linkTarget?: string;
  mode?: number;
  data?: Buffer;
}

/**
 * Unpack `archivePath` into `destDir`, or refuse it whole.
 *
 * Returns the destination-relative paths written, in archive order. Throws
 * `ArchiveEntryRefused` when any entry would land outside `destDir`, before
 * anything at all has been created.
 */
export async function extractArchiveInto(
  archivePath: string,
  destDir: string,
  options: ExtractArchiveOptions = {},
): Promise<string[]> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const stripComponents = options.stripComponents ?? 0;

  const raw = await fs.readFile(archivePath);
  const format = sniffFormat(raw) ?? options.format;
  if (!format) {
    throw new Error(
      `${path.basename(archivePath)}: not a gzip, bzip2, xz or zip archive, so it was not unpacked.`,
    );
  }

  const entries =
    format === 'zip'
      ? readZipEntries(raw, archivePath, maxBytes)
      : readTarEntries(decompressTar(raw, format, archivePath, maxBytes), archivePath);

  await fs.mkdir(destDir, { recursive: true });
  const destReal = await fs.realpath(destDir);

  // Every entry is judged before any of them is created.
  for (const entry of entries) refuseEscapingEntry(entry, archivePath);

  const written: string[] = [];
  let budget = maxBytes;
  for (const entry of entries) {
    const relative = strip(entry.name, stripComponents);
    if (relative === null) continue;

    const target = path.join(destReal, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });

    // The names were judged lexically above; this asks the filesystem where the
    // containing directory ACTUALLY is, which is the question a symbolic link
    // already on disk answers differently. Same predicate as `contain.ts`.
    const parentReal = await fs.realpath(path.dirname(target));
    if (!isPathWithinDirectory(parentReal, destReal)) {
      throw new ArchiveEntryRefused({
        archivePath,
        entryName: entry.name,
        refusal: 'parent-outside-destination',
      });
    }

    if (entry.kind === 'directory') {
      await fs.mkdir(target, { recursive: true });
      written.push(relative);
      continue;
    }

    // Never write THROUGH something already standing at the leaf. An archive
    // that names the same member twice, once as a link and once as a file, is
    // the hard-link overwrite shape; unlinking first makes the second member
    // land where this check looked.
    await fs.rm(target, { force: true, recursive: false }).catch(() => undefined);

    if (entry.kind === 'symlink') {
      await fs.symlink(entry.linkTarget ?? '', target);
      written.push(relative);
      continue;
    }

    if (entry.kind === 'hardlink') {
      // The target is named from the archive root, so it is stripped the same
      // way the member is; one whose target strips away has nothing to link to.
      const source = strip(path.posix.normalize(entry.linkTarget ?? ''), stripComponents);
      if (source === null) continue;
      await fs.link(path.join(destReal, source), target);
      written.push(relative);
      continue;
    }

    const data = entry.data ?? Buffer.alloc(0);
    budget -= data.length;
    if (budget < 0) {
      throw new Error(
        `${path.basename(archivePath)}: unpacks to more than ${maxBytes} bytes, so it was not unpacked.`,
      );
    }
    await fs.writeFile(target, data, { mode: fileMode(entry.mode) });
    written.push(relative);
  }

  return written;
}

/**
 * The permission bits the archive recorded, and nothing else.
 *
 * Faithful on purpose, including a member recorded mode 000: `check` scores a
 * downloaded package on what it could READ, and a member the archive ships
 * unreadable has to arrive unreadable or the coverage ledger counts a file
 * nobody read as examined (#508). What is dropped is the high half — setuid,
 * setgid and the sticky bit are not restored from an archive HMA did not
 * author. Directory modes are not restored at all: a directory recorded 000
 * would be one this unpacker could not then write its own members into, and
 * nothing downstream reads a directory's mode.
 */
function fileMode(mode: number | undefined): number {
  if (mode === undefined) return 0o644;
  return mode & 0o777;
}

/**
 * Drop `count` leading components, as `tar --strip-components` does. A member
 * with no components left is not an error and not a write: it is skipped.
 */
function strip(name: string, count: number): string | null {
  const parts = name.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.length <= count) return null;
  return parts.slice(count).join('/');
}

/**
 * The containment decision, in one place.
 *
 * Judged on the name the ARCHIVE carries, before any component of it has been
 * joined onto a real directory. Both separators are treated as separators here
 * even on POSIX, where a backslash is a legal filename byte: an archive whose
 * member is named `..\planted` is not a package, it is a probe for an unpacker
 * that splits differently from the one that built it.
 */
function refuseEscapingEntry(entry: ArchiveEntry, archivePath: string): void {
  const refuse = (refusal: ArchiveRefusalCause, linkTarget?: string): never => {
    throw new ArchiveEntryRefused({ archivePath, entryName: entry.name, refusal, linkTarget });
  };

  if (entry.kind === 'other') refuse('unsupported-entry-type');
  if (isAbsoluteEntryName(entry.name)) refuse('absolute-name');
  if (climbsOut(entry.name)) refuse('name-escapes-destination');

  if (entry.kind === 'symlink' || entry.kind === 'hardlink') {
    const target = entry.linkTarget ?? '';
    if (isAbsoluteEntryName(target)) refuse('link-escapes-destination', target);
    // A symbolic link resolves against the directory that holds it; a tar hard
    // link names its target from the archive root. Same refusal, two origins.
    const base = entry.kind === 'symlink' ? posixDirname(entry.name) : '';
    if (climbsOut(path.posix.join(base, target.split('\\').join('/')))) {
      refuse('link-escapes-destination', target);
    }
  }
}

function posixDirname(name: string): string {
  const dir = path.posix.dirname(name.split('\\').join('/'));
  return dir === '.' || dir === '/' ? '' : dir;
}

function isAbsoluteEntryName(name: string): boolean {
  return /^[/\\]/.test(name) || /^[A-Za-z]:[/\\]/.test(name);
}

/** True when the name, read as a relative path, reaches above its own root. */
function climbsOut(name: string): boolean {
  const normalized = path.posix.normalize(name.split('\\').join('/'));
  return normalized === '..' || normalized.indexOf('../') === 0;
}

// ---------------------------------------------------------------------------
// Container sniffing and decompression
// ---------------------------------------------------------------------------

function sniffFormat(raw: Buffer): ArchiveFormat | undefined {
  if (raw.length >= 2 && raw[0] === 0x1f && raw[1] === 0x8b) return 'tar.gz';
  if (raw.length >= 3 && raw[0] === 0x42 && raw[1] === 0x5a && raw[2] === 0x68) return 'tar.bz2';
  if (raw.length >= 6 && raw.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) {
    return 'tar.xz';
  }
  if (raw.length >= 4 && raw[0] === 0x50 && raw[1] === 0x4b && (raw[2] === 0x03 || raw[2] === 0x05)) {
    return 'zip';
  }
  return undefined;
}

function decompressTar(
  raw: Buffer,
  format: ArchiveFormat,
  archivePath: string,
  maxBytes: number,
): Buffer {
  if (format === 'tar.gz') return zlib.gunzipSync(raw, { maxOutputLength: maxBytes });
  if (format === 'tar.bz2') return bunzip2(raw, maxBytes);
  if (format === 'tar.xz') {
    try {
      return execFileSync('xz', ['--decompress', '--stdout'], {
        input: raw,
        maxBuffer: maxBytes,
        windowsHide: true,
      });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ENOENT') {
        throw new Error(
          `${path.basename(archivePath)}: xz-compressed, and xz(1) is not on PATH, so its ` +
            `entries could not be inspected and it was not unpacked.`,
        );
      }
      throw err;
    }
  }
  throw new Error(`${path.basename(archivePath)}: ${format} is not a tar container.`);
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------

function readTarEntries(tar: Buffer, archivePath: string): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  let offset = 0;
  // Set by the pseudo-entry that precedes the member they describe.
  let longName: string | undefined;
  let longLink: string | undefined;

  while (offset + TAR_BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK);
    if (isZeroBlock(header)) break;
    if (!tarChecksumOk(header)) {
      throw new Error(
        `${path.basename(archivePath)}: corrupt tar header at byte ${offset}, so it was not unpacked.`,
      );
    }

    const size = readTarNumber(header, 124, 12);
    const dataStart = offset + TAR_BLOCK;
    const data = tar.subarray(dataStart, Math.min(dataStart + size, tar.length));
    offset = dataStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;

    const typeflag = header[156] === 0 ? '0' : String.fromCharCode(header[156]);

    if (typeflag === 'L') {
      longName = cString(data);
      continue;
    }
    if (typeflag === 'K') {
      longLink = cString(data);
      continue;
    }
    if (typeflag === 'x' || typeflag === 'X' || typeflag === 'g') {
      const pax = readPax(data);
      if (typeflag !== 'g') {
        if (pax.path !== undefined) longName = pax.path;
        if (pax.linkpath !== undefined) longLink = pax.linkpath;
      }
      continue;
    }
    if (typeflag === 'V') continue; // volume label: names no member

    const prefix = cString(header.subarray(345, 500));
    const bare = cString(header.subarray(0, 100));
    const name = longName ?? (prefix === '' ? bare : `${prefix}/${bare}`);
    const linkTarget = longLink ?? cString(header.subarray(157, 257));
    longName = undefined;
    longLink = undefined;

    const kind = tarKind(typeflag, name);
    entries.push({
      name,
      kind,
      mode: readTarNumber(header, 100, 8),
      ...(kind === 'symlink' || kind === 'hardlink' ? { linkTarget } : {}),
      ...(kind === 'file' ? { data: Buffer.from(data) } : {}),
    });
  }

  return entries;
}

function tarKind(typeflag: string, name: string): ArchiveEntry['kind'] {
  switch (typeflag) {
    case '0':
    case '7':
      // A ustar writer may record a directory as a plain member with a
      // trailing slash and no size.
      return name.length > 0 && name.charAt(name.length - 1) === '/' ? 'directory' : 'file';
    case '5':
      return 'directory';
    case '1':
      return 'hardlink';
    case '2':
      return 'symlink';
    default:
      // '3' char device, '4' block device, '6' fifo, and the GNU sparse and
      // multi-volume types. None of them is a thing this unpacker creates.
      return 'other';
  }
}

function isZeroBlock(block: Buffer): boolean {
  for (let i = 0; i < block.length; i++) if (block[i] !== 0) return false;
  return true;
}

function cString(field: Buffer): string {
  const end = field.indexOf(0);
  return field.toString('utf8', 0, end === -1 ? field.length : end);
}

/** Octal, or GNU's base-256 form for a field that will not fit in octal. */
function readTarNumber(header: Buffer, offset: number, length: number): number {
  const field = header.subarray(offset, offset + length);
  if (field.length > 0 && (field[0] & 0x80) !== 0) {
    let value = field[0] & 0x7f;
    for (let i = 1; i < field.length; i++) value = value * 256 + field[i];
    return value;
  }
  const text = field.toString('ascii').split('\0').join(' ').trim();
  if (text === '') return 0;
  const parsed = parseInt(text, 8);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * The checksum is computed with its own field read as eight spaces. Both the
 * signed and unsigned sums are accepted because historical writers produced
 * both, which is the same allowance `tar` itself makes.
 */
function tarChecksumOk(header: Buffer): boolean {
  const recorded = readTarNumber(header, 148, 8);
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < TAR_BLOCK; i++) {
    const byte = i >= 148 && i < 156 ? 0x20 : header[i];
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  return recorded === unsigned || recorded === signed;
}

/** `<len> <key>=<value>\n` records. Only `path` and `linkpath` are read. */
function readPax(data: Buffer): { path?: string; linkpath?: string } {
  const out: { path?: string; linkpath?: string } = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const length = parseInt(data.toString('ascii', offset, space), 10);
    if (!Number.isFinite(length) || length <= 0 || offset + length > data.length) break;
    const record = data.toString('utf8', space + 1, offset + length).replace(/\n$/, '');
    const equals = record.indexOf('=');
    if (equals !== -1) {
      const key = record.slice(0, equals);
      if (key === 'path') out.path = record.slice(equals + 1);
      if (key === 'linkpath') out.linkpath = record.slice(equals + 1);
    }
    offset += length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------

const ZIP_EOCD = 0x06054b50;
const ZIP_EOCD64 = 0x06064b50;
const ZIP_EOCD64_LOCATOR = 0x07064b50;
const ZIP_CENTRAL = 0x02014b50;
const ZIP_LOCAL = 0x04034b50;

function readZipEntries(zip: Buffer, archivePath: string, maxBytes: number): ArchiveEntry[] {
  const label = path.basename(archivePath);
  const eocd = findEocd(zip);
  if (eocd === -1) throw new Error(`${label}: no zip end-of-central-directory record.`);

  let count = zip.readUInt16LE(eocd + 10);
  let start = zip.readUInt32LE(eocd + 16);

  // ZIP64, when either field is saturated.
  if (count === 0xffff || start === 0xffffffff) {
    const locator = eocd - 20;
    if (locator >= 0 && zip.readUInt32LE(locator) === ZIP_EOCD64_LOCATOR) {
      const record = Number(zip.readBigUInt64LE(locator + 8));
      if (record >= 0 && record + 56 <= zip.length && zip.readUInt32LE(record) === ZIP_EOCD64) {
        count = Number(zip.readBigUInt64LE(record + 32));
        start = Number(zip.readBigUInt64LE(record + 48));
      }
    }
  }

  const entries: ArchiveEntry[] = [];
  let offset = start;
  let budget = maxBytes;
  for (let i = 0; i < count; i++) {
    if (offset + 46 > zip.length || zip.readUInt32LE(offset) !== ZIP_CENTRAL) {
      throw new Error(`${label}: corrupt zip central directory at byte ${offset}.`);
    }
    const madeBy = zip.readUInt16LE(offset + 4);
    const method = zip.readUInt16LE(offset + 10);
    const compressedSize = zip.readUInt32LE(offset + 20);
    const uncompressedSize = zip.readUInt32LE(offset + 24);
    const nameLength = zip.readUInt16LE(offset + 28);
    const extraLength = zip.readUInt16LE(offset + 30);
    const commentLength = zip.readUInt16LE(offset + 32);
    const external = zip.readUInt32LE(offset + 38);
    const localOffset = zip.readUInt32LE(offset + 42);
    const name = zip.toString('utf8', offset + 46, offset + 46 + nameLength);
    offset += 46 + nameLength + extraLength + commentLength;

    budget -= uncompressedSize;
    if (budget < 0) {
      throw new Error(`${label}: unpacks to more than ${maxBytes} bytes, so it was not unpacked.`);
    }

    // The unix mode lives in the top half of the external attributes, and only
    // when the writer said it was a unix host. That is where a zip records
    // that a member is a symbolic link; the link's target is its content.
    const unixMode = (madeBy >>> 8) === 3 ? (external >>> 16) & 0xffff : 0;
    const isSymlink = (unixMode & 0xf000) === 0xa000;
    const isDirectory = !isSymlink && name.length > 0 && name.charAt(name.length - 1) === '/';

    if (isDirectory) {
      entries.push({ name, kind: 'directory' });
      continue;
    }

    const data = readZipData(zip, label, localOffset, method, compressedSize, uncompressedSize);
    if (isSymlink) {
      entries.push({ name, kind: 'symlink', linkTarget: data.toString('utf8') });
    } else {
      // A zip written by a non-unix host records no mode at all, which is not
      // the same statement as "mode 000" and must not become one.
      entries.push({
        name,
        kind: 'file',
        ...(unixMode === 0 ? {} : { mode: unixMode & 0o777 }),
        data,
      });
    }
  }
  return entries;
}

function findEocd(zip: Buffer): number {
  const earliest = Math.max(0, zip.length - 0xffff - 22);
  for (let i = zip.length - 22; i >= earliest; i--) {
    if (zip.readUInt32LE(i) === ZIP_EOCD) return i;
  }
  return -1;
}

function readZipData(
  zip: Buffer,
  label: string,
  localOffset: number,
  method: number,
  compressedSize: number,
  uncompressedSize: number,
): Buffer {
  if (localOffset + 30 > zip.length || zip.readUInt32LE(localOffset) !== ZIP_LOCAL) {
    throw new Error(`${label}: corrupt zip local header at byte ${localOffset}.`);
  }
  const nameLength = zip.readUInt16LE(localOffset + 26);
  const extraLength = zip.readUInt16LE(localOffset + 28);
  const start = localOffset + 30 + nameLength + extraLength;
  const body = zip.subarray(start, start + compressedSize);

  if (method === 0) return Buffer.from(body);
  if (method === 8) {
    return zlib.inflateRawSync(body, { maxOutputLength: Math.max(uncompressedSize, 1) });
  }
  throw new Error(`${label}: zip compression method ${method} is not supported.`);
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------

/**
 * A bzip2 decoder, in the shape bzip2's own `decompress.c` describes it:
 * per block, a Huffman-coded MTF/run-length symbol stream, then the inverse
 * Burrows-Wheeler transform keyed on the block's origin pointer, then the
 * outer run-length decoding. Block CRCs are checked, and so is the combined
 * stream CRC: a decoder that silently returns wrong bytes would hand this
 * module a tar header it never inspected.
 */
function bunzip2(raw: Buffer, maxBytes: number): Buffer {
  if (raw.length < 4 || raw[0] !== 0x42 || raw[1] !== 0x5a || raw[2] !== 0x68) {
    throw new Error('not a bzip2 stream');
  }
  const level = raw[3] - 0x30;
  if (level < 1 || level > 9) throw new Error('bzip2 stream has no block size');
  const maxBlock = level * 100000;

  const bits = new BitReader(raw, 4);
  const chunks: Buffer[] = [];
  let total = 0;
  let combined = 0;

  for (;;) {
    const hi = bits.read(24);
    const lo = bits.read(24);
    if (hi === 0x177245 && lo === 0x385090) {
      const recorded = bits.read32();
      if (recorded !== combined) throw new Error('bzip2 stream CRC mismatch');
      break;
    }
    if (hi !== 0x314159 || lo !== 0x265359) throw new Error('bzip2 block magic mismatch');

    const blockCrc = bits.read32();
    if (bits.read(1) !== 0) throw new Error('randomized bzip2 blocks are not supported');
    const origPtr = bits.read(24);

    const block = bunzip2Block(bits, maxBlock, origPtr);
    const crc = bzip2Crc(block);
    if (crc !== blockCrc) throw new Error('bzip2 block CRC mismatch');
    combined = (((combined << 1) | (combined >>> 31)) ^ crc) >>> 0;

    total += block.length;
    if (total > maxBytes) throw new Error('bzip2 stream expands past the size ceiling');
    chunks.push(block);
  }

  return Buffer.concat(chunks, total);
}

function bunzip2Block(bits: BitReader, maxBlock: number, origPtr: number): Buffer {
  // Which byte values the block uses, as 16 groups of 16.
  const used: number[] = [];
  const groups = bits.read(16);
  for (let group = 0; group < 16; group++) {
    if ((groups & (0x8000 >>> group)) === 0) continue;
    const members = bits.read(16);
    for (let bit = 0; bit < 16; bit++) {
      if ((members & (0x8000 >>> bit)) !== 0) used.push(group * 16 + bit);
    }
  }
  if (used.length === 0) throw new Error('bzip2 block uses no symbols');
  const alphaSize = used.length + 2;

  const groupCount = bits.read(3);
  if (groupCount < 2 || groupCount > 6) throw new Error('bzip2 block has a bad group count');
  const selectorCount = bits.read(15);
  if (selectorCount < 1) throw new Error('bzip2 block has no selectors');

  const selectorMtf: number[] = [];
  for (let i = 0; i < selectorCount; i++) {
    let j = 0;
    while (bits.read(1) === 1) {
      j++;
      if (j >= groupCount) throw new Error('bzip2 selector out of range');
    }
    selectorMtf.push(j);
  }
  const order: number[] = [];
  for (let i = 0; i < groupCount; i++) order.push(i);
  const selectors = selectorMtf.map((j) => {
    const value = order.splice(j, 1)[0];
    order.unshift(value);
    return value;
  });

  const lengths: number[][] = [];
  for (let t = 0; t < groupCount; t++) {
    let curr = bits.read(5);
    const row: number[] = [];
    for (let s = 0; s < alphaSize; s++) {
      for (;;) {
        if (curr < 1 || curr > 20) throw new Error('bzip2 code length out of range');
        if (bits.read(1) === 0) break;
        curr += bits.read(1) === 0 ? 1 : -1;
      }
      row.push(curr);
    }
    lengths.push(row);
  }

  const tables = lengths.map((row) => buildHuffmanTable(row, alphaSize));

  const mtf = used.slice();
  const counts = new Int32Array(256);
  const bwt = new Uint32Array(maxBlock);
  let length = 0;
  const eob = alphaSize - 1;

  let selectorIndex = -1;
  let groupPos = 0;
  let table = tables[0];
  const nextSymbol = (): number => {
    if (groupPos === 0) {
      selectorIndex++;
      if (selectorIndex >= selectors.length) throw new Error('bzip2 block ran out of selectors');
      groupPos = 50;
      table = tables[selectors[selectorIndex]];
    }
    groupPos--;
    let bitCount = table.minLength;
    let value = bits.read(bitCount);
    while (value > table.limit[bitCount]) {
      bitCount++;
      if (bitCount > table.maxLength) throw new Error('bzip2 symbol is not in the code');
      value = value * 2 + bits.read(1);
    }
    const index = value - table.base[bitCount];
    if (index < 0 || index >= table.perm.length) throw new Error('bzip2 symbol out of range');
    return table.perm[index];
  };

  let symbol = nextSymbol();
  while (symbol !== eob) {
    if (symbol <= 1) {
      // RUNA and RUNB, a bijective base-two count of repeats of mtf[0].
      let run = 0;
      let weight = 1;
      while (symbol <= 1) {
        run += (symbol + 1) * weight;
        weight *= 2;
        if (weight > maxBlock * 2) throw new Error('bzip2 run length out of range');
        symbol = nextSymbol();
      }
      const byte = mtf[0];
      if (length + run > maxBlock) throw new Error('bzip2 block is longer than its declared size');
      counts[byte] += run;
      for (let i = 0; i < run; i++) bwt[length++] = byte;
      continue;
    }
    const byte = mtf.splice(symbol - 1, 1)[0];
    mtf.unshift(byte);
    if (length + 1 > maxBlock) throw new Error('bzip2 block is longer than its declared size');
    counts[byte]++;
    bwt[length++] = byte;
    symbol = nextSymbol();
  }

  if (origPtr >= length) throw new Error('bzip2 origin pointer is outside the block');

  // Inverse BWT: each cell keeps its byte in the low eight bits and the index
  // of the cell that follows it in the rest.
  const running = new Int32Array(257);
  for (let i = 0; i < 256; i++) running[i + 1] = running[i] + counts[i];
  for (let i = 0; i < length; i++) {
    const byte = bwt[i] & 0xff;
    bwt[running[byte]] |= i << 8;
    running[byte]++;
  }

  const out: number[] = [];
  let pos = bwt[origPtr] >>> 8;
  let previous = -1;
  let run = 0;
  for (let i = 0; i < length; i++) {
    const byte = bwt[pos] & 0xff;
    pos = bwt[pos] >>> 8;
    // The outer run-length coding: four equal bytes, then a count of extras.
    if (run === 4) {
      for (let k = 0; k < byte; k++) out.push(previous);
      run = 0;
      previous = -1;
      continue;
    }
    if (byte === previous) run++;
    else {
      previous = byte;
      run = 1;
    }
    out.push(byte);
  }
  return Buffer.from(out);
}

interface HuffmanTable {
  minLength: number;
  maxLength: number;
  limit: number[];
  base: number[];
  perm: number[];
}

function buildHuffmanTable(lengths: number[], alphaSize: number): HuffmanTable {
  let minLength = 32;
  let maxLength = 0;
  for (let i = 0; i < alphaSize; i++) {
    if (lengths[i] < minLength) minLength = lengths[i];
    if (lengths[i] > maxLength) maxLength = lengths[i];
  }
  const perm: number[] = [];
  for (let length = minLength; length <= maxLength; length++) {
    for (let s = 0; s < alphaSize; s++) if (lengths[s] === length) perm.push(s);
  }
  const base: number[] = new Array(maxLength + 2).fill(0);
  for (let i = 0; i < alphaSize; i++) base[lengths[i] + 1]++;
  for (let i = 1; i < base.length; i++) base[i] += base[i - 1];
  const limit: number[] = new Array(maxLength + 2).fill(0);
  let vector = 0;
  for (let length = minLength; length <= maxLength; length++) {
    vector += base[length + 1] - base[length];
    limit[length] = vector - 1;
    vector *= 2;
  }
  for (let length = minLength + 1; length <= maxLength; length++) {
    base[length] = (limit[length - 1] + 1) * 2 - base[length];
  }
  return { minLength, maxLength, limit, base, perm };
}

/** bzip2's CRC: the unreflected CRC-32, fed most significant bit first. */
const BZIP2_CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i << 24;
    for (let bit = 0; bit < 8; bit++) {
      value = (value & 0x80000000) !== 0 ? ((value << 1) ^ 0x04c11db7) : value << 1;
    }
    table[i] = value;
  }
  return table;
})();

function bzip2Crc(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = ((crc << 8) ^ BZIP2_CRC_TABLE[((crc >>> 24) ^ data[i]) & 0xff]) >>> 0;
  }
  return (~crc) >>> 0;
}

/** Most significant bit first, which is the order bzip2 writes. */
class BitReader {
  private byteIndex: number;
  private buffer = 0;
  private count = 0;

  constructor(private readonly bytes: Buffer, start: number) {
    this.byteIndex = start;
  }

  /** Up to 24 bits; the accumulator holds at most 31 at a time. */
  read(width: number): number {
    while (this.count < width) {
      if (this.byteIndex >= this.bytes.length) throw new Error('bzip2 stream ends mid-symbol');
      this.buffer = ((this.buffer << 8) | this.bytes[this.byteIndex++]) >>> 0;
      this.count += 8;
    }
    const shift = this.count - width;
    const value = (this.buffer >>> shift) & ((1 << width) - 1);
    this.count = shift;
    this.buffer = this.buffer & ((1 << shift) - 1);
    return value >>> 0;
  }

  /** 32 bits, in two halves: the accumulator above cannot hold a 33rd. */
  read32(): number {
    return ((this.read(16) * 0x10000) + this.read(16)) >>> 0;
  }
}
