/**
 * Archive writers for the extraction-fence cases.
 *
 * The fence's cases need archives whose entries no packaging tool will produce
 * on request — a member named `../planted`, a member whose name is absolute, a
 * symbolic link to a directory outside the destination — and they must build
 * them in a temporary directory rather than commit them: `test-fixtures/`
 * shipped deliberately vulnerable content to every installer once, and a
 * traversal archive is exactly the shape that must not sit in a published tree.
 *
 * So the containers are written here, byte by byte. That also removes the
 * matrix's dependency on host packaging binaries, which is not incidental:
 * `zip(1)` and `bzip2(1)` are both absent from minimal Linux images, so a
 * fixture built by spawning them would be a case that silently does not run
 * where it most needs to. `xz(1)` is the one exception — no compressor for it
 * ships with Node and writing one for a fixture is out of proportion — so the
 * `.tar.xz` cases probe for it with `hasXz()` and say so when it is missing.
 *
 * Nothing here is imported by `src/`. It exists to hand the fence archives it
 * must refuse.
 */
import { execFileSync } from 'node:child_process';

export interface TarMember {
  name: string;
  kind: 'file' | 'directory' | 'symlink' | 'hardlink';
  /** For `symlink` and `hardlink`. */
  linkTarget?: string;
  /** For `file`. */
  data?: Buffer;
  mode?: number;
}

export interface ZipMember {
  name: string;
  /** A symbolic link's target IS its content; the mode says which it is. */
  data: Buffer;
  kind: 'file' | 'directory' | 'symlink';
}

const TAR_BLOCK = 512;

/** A ustar archive. Names and link targets stay under the 100-byte fields. */
export function tarBytes(members: TarMember[]): Buffer {
  const blocks: Buffer[] = [];
  for (const member of members) {
    const data = member.kind === 'file' ? (member.data ?? Buffer.alloc(0)) : Buffer.alloc(0);
    blocks.push(tarHeader(member, data.length));
    if (data.length > 0) {
      const padded = Buffer.alloc(Math.ceil(data.length / TAR_BLOCK) * TAR_BLOCK);
      data.copy(padded);
      blocks.push(padded);
    }
  }
  // Two zero blocks close the archive.
  blocks.push(Buffer.alloc(TAR_BLOCK * 2));
  return Buffer.concat(blocks);
}

function tarHeader(member: TarMember, size: number): Buffer {
  const header = Buffer.alloc(TAR_BLOCK);
  const typeflag = { file: '0', directory: '5', hardlink: '1', symlink: '2' }[member.kind];
  const defaultMode = member.kind === 'directory' ? 0o755 : member.kind === 'symlink' ? 0o777 : 0o644;

  header.write(member.name, 0, 100, 'utf8');
  writeOctalField(header, member.mode ?? defaultMode, 100, 8);
  writeOctalField(header, 0, 108, 8); // uid
  writeOctalField(header, 0, 116, 8); // gid
  writeOctalField(header, size, 124, 12);
  writeOctalField(header, 0, 136, 12); // mtime
  header.write('        ', 148, 8, 'ascii'); // checksum, counted as spaces
  header.write(typeflag, 156, 1, 'ascii');
  header.write(member.linkTarget ?? '', 157, 100, 'utf8');
  header.write('ustar\0', 257, 6, 'binary');
  header.write('00', 263, 2, 'ascii');

  let sum = 0;
  for (let i = 0; i < TAR_BLOCK; i++) sum += header[i];
  header.write(sum.toString(8).padStart(6, '0'), 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function writeOctalField(buffer: Buffer, value: number, offset: number, length: number): void {
  buffer.write(value.toString(8).padStart(length - 1, '0'), offset, length - 1, 'ascii');
  buffer[offset + length - 1] = 0;
}

/**
 * A zip with stored (uncompressed) members. A symbolic link is a member whose
 * unix mode says `S_IFLNK` in the top half of the external attributes and
 * whose content is the target — the only way a zip records one, and the reason
 * an unpacker that ignores the external attributes cannot see it coming.
 */
export function zipBytes(members: ZipMember[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const member of members) {
    const name = Buffer.from(member.name, 'utf8');
    const data = member.kind === 'directory' ? Buffer.alloc(0) : member.data;
    const crc = zipCrc32(data);
    const mode =
      member.kind === 'symlink' ? 0o120777 : member.kind === 'directory' ? 0o040755 : 0o100644;

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4); // made by a unix host
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(mode * 0x10000, 38);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);

    locals.push(local, data);
    centrals.push(central);
    offset += local.length + data.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(members.length, 8);
  end.writeUInt16LE(members.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, directory, end]);
}

const ZIP_CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i;
    for (let bit = 0; bit < 8; bit++) {
      value = (value & 1) !== 0 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    }
    table[i] = value;
  }
  return table;
})();

function zipCrc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ ZIP_CRC_TABLE[(crc ^ data[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------

/**
 * A single-block bzip2 stream.
 *
 * Deliberately the simplest VALID encoder rather than a good one: two Huffman
 * groups carrying the same flat, complete code, every selector pointing at the
 * first. The output is real bzip2 — `bzip2 -d` and Python's `bz2` both read it
 * — and it compresses badly, which for a three-header tar does not matter.
 */
export function bzip2Bytes(input: Buffer): Buffer {
  const writer = new BitWriter();
  writer.writeByte(0x42); // B
  writer.writeByte(0x5a); // Z
  writer.writeByte(0x68); // h
  writer.writeByte(0x39); // '9': 900k blocks, so one block holds these fixtures

  const rle = rle1Encode(input);
  const { last, origin } = burrowsWheeler(rle);
  const { symbols, used } = moveToFront(last);
  const alphaSize = used.length + 2;
  const lengths = flatCodeLengths(alphaSize);
  const codes = canonicalCodes(lengths);
  const crc = bzip2Crc(input);

  writer.write(24, 0x314159);
  writer.write(24, 0x265359);
  writer.write32(crc);
  writer.write(1, 0); // not randomized
  writer.write(24, origin);

  let groupFlags = 0;
  for (let group = 0; group < 16; group++) {
    if (used.some((byte) => byte >>> 4 === group)) groupFlags |= 0x8000 >>> group;
  }
  writer.write(16, groupFlags);
  for (let group = 0; group < 16; group++) {
    if ((groupFlags & (0x8000 >>> group)) === 0) continue;
    let members = 0;
    for (let bit = 0; bit < 16; bit++) {
      if (used.indexOf(group * 16 + bit) !== -1) members |= 0x8000 >>> bit;
    }
    writer.write(16, members);
  }

  const selectorCount = Math.max(1, Math.ceil(symbols.length / 50));
  writer.write(3, 2); // two groups
  writer.write(15, selectorCount);
  for (let i = 0; i < selectorCount; i++) writer.write(1, 0); // always the first

  for (let group = 0; group < 2; group++) {
    let curr = lengths[0];
    writer.write(5, curr);
    for (let s = 0; s < alphaSize; s++) {
      while (curr < lengths[s]) {
        writer.write(2, 0b10);
        curr++;
      }
      while (curr > lengths[s]) {
        writer.write(2, 0b11);
        curr--;
      }
      writer.write(1, 0);
    }
  }

  for (const symbol of symbols) writer.write(lengths[symbol], codes[symbol]);

  writer.write(24, 0x177245);
  writer.write(24, 0x385090);
  writer.write32(crc); // one block, so the combined CRC is this block's
  return writer.finish();
}

/** Four equal bytes, then a count of up to 251 more. */
function rle1Encode(input: Buffer): Buffer {
  const out: number[] = [];
  let i = 0;
  while (i < input.length) {
    const byte = input[i];
    let run = 1;
    while (i + run < input.length && input[i + run] === byte && run < 255) run++;
    if (run >= 4) {
      out.push(byte, byte, byte, byte, run - 4);
    } else {
      for (let k = 0; k < run; k++) out.push(byte);
    }
    i += run;
  }
  return Buffer.from(out);
}

/**
 * The last column of the sorted rotation matrix, and where rotation zero
 * landed. Sorted by rank doubling, which is fast enough for a fixture and
 * immune to the quadratic blow-up a naive rotation sort hits on the long runs
 * of NUL bytes a tar header is mostly made of.
 */
function burrowsWheeler(data: Buffer): { last: Buffer; origin: number } {
  const n = data.length;
  if (n === 0) return { last: Buffer.alloc(0), origin: 0 };

  let rank = new Int32Array(n);
  for (let i = 0; i < n; i++) rank[i] = data[i];
  const order: number[] = [];
  for (let i = 0; i < n; i++) order.push(i);

  for (let step = 1; step < n; step *= 2) {
    const tail = (i: number): number => rank[(i + step) % n];
    order.sort((a, b) => rank[a] - rank[b] || tail(a) - tail(b));
    const next = new Int32Array(n);
    let distinct = 0;
    for (let i = 1; i < n; i++) {
      const a = order[i - 1];
      const b = order[i];
      if (rank[a] !== rank[b] || tail(a) !== tail(b)) distinct++;
      next[b] = distinct;
    }
    rank = next;
    if (distinct === n - 1) break;
  }

  const last = Buffer.alloc(n);
  let origin = 0;
  for (let i = 0; i < n; i++) {
    const rotation = order[i];
    last[i] = data[(rotation + n - 1) % n];
    if (rotation === 0) origin = i;
  }
  return { last, origin };
}

/** Move-to-front, with zero runs in bzip2's bijective base-two coding. */
function moveToFront(last: Buffer): { symbols: number[]; used: number[] } {
  const present = new Array<boolean>(256).fill(false);
  for (let i = 0; i < last.length; i++) present[last[i]] = true;
  const used: number[] = [];
  for (let byte = 0; byte < 256; byte++) if (present[byte]) used.push(byte);

  const table = used.slice();
  const symbols: number[] = [];
  let zeros = 0;
  const flush = (): void => {
    if (zeros === 0) return;
    let run = zeros - 1;
    for (;;) {
      symbols.push(run & 1 ? 1 : 0); // RUNB : RUNA
      if (run < 2) break;
      run = (run - 2) >> 1;
    }
    zeros = 0;
  };

  for (let i = 0; i < last.length; i++) {
    const byte = last[i];
    const at = table.indexOf(byte);
    if (at === 0) {
      zeros++;
      continue;
    }
    flush();
    table.splice(at, 1);
    table.unshift(byte);
    symbols.push(at + 1);
  }
  flush();
  symbols.push(used.length + 1); // end of block
  return { symbols, used };
}

/**
 * A complete prefix code over `alphaSize` symbols with no frequency model:
 * `2^L - alphaSize` symbols get `L-1` bits and the rest get `L`, which sums to
 * exactly one and so decodes under bzip2's canonical tables.
 */
function flatCodeLengths(alphaSize: number): number[] {
  let width = 1;
  while (1 << width < alphaSize) width++;
  const short = (1 << width) - alphaSize;
  const lengths: number[] = [];
  for (let s = 0; s < alphaSize; s++) lengths.push(s < short ? width - 1 : width);
  return lengths;
}

function canonicalCodes(lengths: number[]): number[] {
  const codes = new Array<number>(lengths.length).fill(0);
  let minLength = 32;
  let maxLength = 0;
  for (const length of lengths) {
    if (length < minLength) minLength = length;
    if (length > maxLength) maxLength = length;
  }
  let vector = 0;
  for (let length = minLength; length <= maxLength; length++) {
    for (let s = 0; s < lengths.length; s++) {
      if (lengths[s] !== length) continue;
      codes[s] = vector;
      vector++;
    }
    vector *= 2;
  }
  return codes;
}

const BZIP2_CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i << 24;
    for (let bit = 0; bit < 8; bit++) {
      value = (value & 0x80000000) !== 0 ? (value << 1) ^ 0x04c11db7 : value << 1;
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
  return ~crc >>> 0;
}

/** Most significant bit first, which is the order bzip2 writes. */
class BitWriter {
  private readonly bytes: number[] = [];
  private buffer = 0;
  private count = 0;

  write(width: number, value: number): void {
    for (let bit = width - 1; bit >= 0; bit--) {
      this.buffer = ((this.buffer << 1) | ((value >>> bit) & 1)) & 0xff;
      this.count++;
      if (this.count === 8) {
        this.bytes.push(this.buffer);
        this.buffer = 0;
        this.count = 0;
      }
    }
  }

  write32(value: number): void {
    this.write(16, (value >>> 16) & 0xffff);
    this.write(16, value & 0xffff);
  }

  writeByte(value: number): void {
    this.write(8, value);
  }

  finish(): Buffer {
    if (this.count > 0) this.write(8 - this.count, 0);
    return Buffer.from(this.bytes);
  }
}

// ---------------------------------------------------------------------------
// xz
// ---------------------------------------------------------------------------

/** Whether `xz(1)` is on PATH, which is what the `.tar.xz` cases need. */
export function hasXz(): boolean {
  try {
    execFileSync('xz', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function xzBytes(input: Buffer): Buffer {
  return execFileSync('xz', ['--compress', '--stdout', '-0'], {
    input,
    maxBuffer: 64 * 1024 * 1024,
  });
}
