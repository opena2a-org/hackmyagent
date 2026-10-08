/**
 * The `<!-- soul:tier=… -->` marker is read at four places: `detectTier`, the
 * SOUL-TIER-MISMATCH check (#451), that check's strip of every marker before
 * it reads the file's own words, and the `harden-soul --tier` conflict check.
 * All four go through `strictTierMarker` (the strip through
 * `withoutTierMarkers`), which return exactly what the pattern
 * `/<!--\s*soul:tier=(\S+)\s*-->/i` and its global form returned, in time
 * linear in the file.
 *
 * A tier name that stopped at `<` or `>` was linear too, but it changed which
 * marker counts: `<!--soul:tier=BASIC--><!--x-->` became BASIC, where the
 * pattern reads the unknown tier `BASIC--><!--x` and the tier is inferred from
 * the file, and `harden-soul --tier` still read it the old way.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SoulScanner } from '../../src/soul/scanner';
import { strictTierMarker, withoutTierMarkers } from '../../src/types/lazy-scan';
import { tempDir } from '../helpers/temp-dir';
import { timeScaling, scalesLinearly, describeScaling, RULE } from '../helpers/scaling-time';

// The patterns the readers replace. Do not edit these to make a test pass:
// they define which marker each reader must keep honouring.
const ORACLE = /<!--\s*soul:tier=(\S+)\s*-->/i;
const ORACLE_ALL = /<!--\s*soul:tier=\S+\s*-->/gi;

type Row = (string | number | undefined)[] | null;
const row = (m: RegExpExecArray | RegExpMatchArray | null): Row => m && [m.index, ...m];

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The marker's pieces and near misses, whitespace of every kind `\s` treats
// specially, the brackets the earlier bound stopped at, and letters whose
// case mapping leaves ASCII (long s, dotted capital I, Kelvin sign).
const ALPHABET = [
  '<!--', '-->', '<!--', '-->', 'soul:tier=', 'soul:tier=', 'SOUL:Tier=', 'soul:tier', 'soul:tier =',
  '<!--soul:tier=', '<!-- soul:tier=', '<!--soul:tier=', ' -->', '-->-->', '--->', '--><!--',
  'BASIC', 'agentic', 'x', '->', '--', '-', '>', '<', '<!-',
];
const COMMON = [
  ' ', '  ', '\t', '\n', '\r', '\r\n', '\v', '\f', ' ', ' ', '　', '﻿',
  'a', 'Z', '0', '"', "'", '=', ':', '/', '\\', '\u{1F600}', 'ſ', 'İ', 'K',
];

function generate(rnd: () => number): string {
  const pool = [...ALPHABET, ...ALPHABET, ...COMMON];
  const len = Math.floor(rnd() * 32);
  let s = '';
  for (let i = 0; i < len; i++) s += pool[Math.floor(rnd() * pool.length)];
  return s;
}

const PAD = ' '.repeat(300);
const HAND = [
  '<!--soul:tier=BASIC--><!--x-->',
  '<!--soul:tier=BASIC--><!--x-->\n# Bot\n',
  '<!-- soul:tier=x>y -->\n<!-- soul:tier=BASIC -->',
  '<!--soul:tier=a<!-- soul:tier=AGENTIC -->',
  '<!--soul:tier=x-->', '<!--soul:tier=a-->b-->', '<!-- soul:tier=a-->b -->',
  '<!-- soul:tier= -->', '<!--soul:tier=-->', '<!--soul:tier=--->',
  '<!--' + PAD + 'soul:tier=x' + PAD + '-->',
  '<!--soul:tier=x<!--soul:tier=y -->', '<!--soul:tier=x\n<!--soul:tier=y-->',
  '<!-- SOUL:TIER=Agentic -->', '<!--<!--soul:tier=x-->',
  '<!-- soul:tier=BASIC --> text <!-- soul:tier=AGENTIC -->\n<!--soul:tier=x--><!--soul:tier=y-->',
];

const INPUTS = 100_000;

describe('strictTierMarker and withoutTierMarkers return what the pattern returned', () => {
  it(`identical first match, match from an offset, and strip on ${INPUTS.toLocaleString('en-US')} generated inputs and the hand cases`, () => {
    const rnd = mulberry32(0x7e1e0001);
    const inputs = [...HAND, ...Array.from({ length: INPUTS }, () => generate(rnd))];
    let withMatch = 0;
    const mismatches: { input: string; from?: number; base: unknown; reader: unknown }[] = [];
    const record = (input: string, base: unknown, reader: unknown, from?: number): void => {
      if (JSON.stringify(reader) !== JSON.stringify(base) && mismatches.length < 5) {
        mismatches.push({ input, from, base, reader });
      }
    };
    for (const input of inputs) {
      const expected = row(input.match(ORACLE));
      if (expected !== null) withMatch++;
      record(input, expected, row(strictTierMarker(input)));

      const from = Math.floor(rnd() * (input.length + 1));
      const sticky = new RegExp(ORACLE.source, 'gi');
      sticky.lastIndex = from;
      record(input, row(sticky.exec(input)), row(strictTierMarker(input, from)), from);

      record(input, input.replace(ORACLE_ALL, ''), withoutTierMarkers(input));
    }
    console.log(`tier marker: ${inputs.length} inputs, ${withMatch} with a match, ${mismatches.length} differences`);
    expect(mismatches).toEqual([]);
    // A generator that rarely produces a match would prove little.
    expect(withMatch).toBeGreaterThan(inputs.length / 20);
  });

  it('a marker run into the next comment reads as the pattern read it, not as its first word', () => {
    expect(strictTierMarker('<!--soul:tier=BASIC--><!--x-->\n# Bot\n')?.[1]).toBe('BASIC--><!--x');
    expect(strictTierMarker('<!-- soul:tier=x>y -->\n<!-- soul:tier=BASIC -->')?.[1]).toBe('x>y');
    expect(strictTierMarker('# Bot\n\n<!-- soul:tier=BASIC -->\n')?.[1]).toBe('BASIC');
    expect(withoutTierMarkers('a <!-- soul:tier=BASIC --> b <!--soul:tier=x--><!--y--> c')).toBe('a  b  c');
  });
});

describe('the four readers of the marker go through strictTierMarker', () => {
  it('src/soul/scanner.ts reads and strips the marker with the reader and no pattern of its own', () => {
    const soul = readFileSync(join(__dirname, '..', '..', 'src', 'soul', 'scanner.ts'), 'utf-8');
    expect(soul).toContain('const markerMatch = strictTierMarker(governanceContent);');
    expect(soul).toContain('ALL_TIERS.includes(strictTierMarker(contentForTier)?.[1]?.toUpperCase() as AgentTier)');
    expect(soul).toContain('const ownWords = withoutTierMarkers(contentForTier)');
    expect(soul).toContain('const pinned = strictTierMarker(existingContent)?.[1];');
    const code = soul.split('\n').filter((line) => !/^\s*(?:\/\/|\*|\/\*)/.test(line));
    expect(code.filter((line) => /soul:tier=[(\[\\]/.test(line))).toEqual([]);
  });
});

describe('which marker scan-soul and harden-soul honour', () => {
  const scanner = new SoulScanner();
  const agenticBody = '# Bot\n\nThe agent runs an autonomous loop and executes shell commands.\n';

  function dirWithSoul(content: string): string {
    const dir = tempDir('tier-marker-reader-');
    writeFileSync(join(dir, 'SOUL.md'), content, 'utf-8');
    return dir;
  }

  it('a marker run into the next comment is not honoured: the tier comes from the file and every domain is evaluated', async () => {
    const result = await scanner.scanSoul(dirWithSoul('<!--soul:tier=BASIC--><!--x-->\n' + agenticBody));
    expect(result.agentTier).toBe('AGENTIC');
    expect(result.tierMismatch).toBeUndefined();
    expect(result.domains.filter((d) => d.skippedByTier)).toEqual([]);
  });

  it('a valid marker after one whose tier name holds an angle bracket is not honoured', async () => {
    const result = await scanner.scanSoul(
      dirWithSoul('<!-- soul:tier=x>y -->\n<!-- soul:tier=BASIC -->\n' + agenticBody),
    );
    expect(result.agentTier).toBe('AGENTIC');
    expect(result.tierMismatch).toBeUndefined();
  });

  it('a written marker is still honoured and compared with the file', async () => {
    const result = await scanner.scanSoul(dirWithSoul('<!-- soul:tier=BASIC -->\n' + agenticBody));
    expect(result.agentTier).toBe('BASIC');
    expect(result.tierMismatch?.inferredTier).toBe('AGENTIC');
  });

  it('harden-soul --tier names the marker value scan-soul reads', async () => {
    const dir = dirWithSoul('<!--soul:tier=BASIC--><!--x-->\n' + agenticBody);
    await expect(scanner.hardenSoul(dir, { tier: 'AGENTIC', dryRun: true })).rejects.toThrow(
      '(soul:tier=BASIC--><!--x)',
    );
  });
});

const flood = (unit: string, bytes: number): string =>
  unit.repeat(Math.ceil(bytes / unit.length)).slice(0, bytes);

const SHAPES: { name: string; input: (bytes: number) => string; run: (input: string) => void }[] = [
  {
    name: 'first marker: <!--soul:tier=x with no whitespace or closer',
    input: (n) => flood('<!--soul:tier=x', n),
    run: (s) => void strictTierMarker(s),
  },
  {
    name: 'first marker: <!--soul:tier=x, then a valid marker',
    input: (n) => flood('<!--soul:tier=x', n) + ' <!-- soul:tier=BASIC -->',
    run: (s) => void strictTierMarker(s),
  },
  {
    name: 'first marker: <!-- soul:tier=x followed by whitespace',
    input: (n) => flood('<!-- soul:tier=x ', n),
    run: (s) => void strictTierMarker(s),
  },
  {
    name: 'first marker: soul:tier= after one opener',
    input: (n) => '<!--' + flood('soul:tier=', n),
    run: (s) => void strictTierMarker(s),
  },
  {
    name: 'strip: a valid marker, then <!--soul:tier= with no closer',
    input: (n) => '<!-- soul:tier=BASIC -->\n' + flood('<!--soul:tier=', n),
    run: (s) => void withoutTierMarkers(s),
  },
  {
    name: 'strip: <!--soul:tier=x--> repeated',
    input: (n) => flood('<!--soul:tier=x-->', n),
    run: (s) => void withoutTierMarkers(s),
  },
  {
    name: 'strip: <!-- soul:tier=x followed by whitespace',
    input: (n) => flood('<!-- soul:tier=x ', n),
    run: (s) => void withoutTierMarkers(s),
  },
];

describe('each flood shape costs linear time', () => {
  for (const shape of SHAPES) {
    it(`${shape.name}: ${RULE}`, () => {
      const time = timeScaling(() => shape.run, shape.input);
      console.log(`${shape.name}: ${describeScaling(time)}`);
      expect(scalesLinearly(time), `${shape.name}: ${describeScaling(time)}`).toBe(true);
    });
  }
});
