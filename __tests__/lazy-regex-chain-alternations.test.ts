/**
 * The alternations of `WORD.*WORD` chains in src/hardening/scanner.ts stop
 * being quadratic (cubic with three words) on a line that repeats a chain's
 * first words, and still return exactly what the patterns returned.
 *
 *   SUPPLY-007                copy the command into a terminal, right-click open
 *   SKILL-011                 browser data and safari cookies
 *   NEMO-003                  policy reload
 *   NEMO-008                  verify digest, validate hash, check integrity
 *   A2A-002                   authentication middleware
 *   SOUL-BYPASS               security validation disabled
 *   SOUL-UNVERIFIABLE-CLAIM   OpenA2A Registry trust claim
 *   SOUL-CONSENT              external service, irrevocable consent
 *   SOUL-COMPLETENESS         capability declarations
 *
 * These are the chains WordChainRegExp does not take: the chain is one branch
 * of an alternation, or a word holds a class, a `(?:a|b)` group or a
 * lookbehind. Each `.*` runs to the end of the line and backs off to look for
 * the next word, from every occurrence of the word before it. The scanned file
 * comes from whoever wrote the skill, script or SOUL.md, so a scan that stalls
 * on it is a way to avoid being scanned: one 16 KiB line of `copy command `
 * took 3.5 s in the SUPPLY-007 check, and one 32 KiB line of
 * `security validation ` took 11.7 s in the SOUL checks.
 *
 * Each site now holds a WordChainAlternationRegExp (src/types/lazy-scan.ts)
 * built from its unchanged literal. The source suite requires every literal
 * in the file that the class accepts to be wrapped, and the wrapped ones to be
 * exactly the oracles below. The differential suite requires each wrapped
 * pattern to return what its oracle returns, with the same lastIndex, over
 * 100,000 generated inputs per site plus hand cases. The timing suite covers
 * each flood shape at 512 KiB and 1 MiB, and the detection suite runs the real
 * checks on 1 MiB files.
 */
import { describe, it, expect } from 'vitest';
import * as fsp from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import ts from 'typescript';
import { HardeningScanner } from '../src/hardening/scanner';
import { WordChainAlternationRegExp } from '../src/types/lazy-scan';
import { tempDir } from './helpers/temp-dir';
import { timeDoubling } from './helpers/doubling-time';

const KiB = 1024;
const MiB = 1024 * KiB;

interface Site {
  oracle: RegExp;
  /** The words of every branch, for the input generator. */
  words: string[];
  /** Flood units: each repeats the start of a chain without its end. */
  floods: string[];
}

// The patterns as they were before the change. Do not edit these to make a
// test pass: they define what each site must keep matching.
const SITES: Record<string, Site> = {
  'SUPPLY-007 copy command': {
    oracle: /copy.*(?:command|script).*terminal/i,
    words: ['copy', 'command', 'script', 'terminal', 'commandscript'],
    floods: ['copy command ', 'copy script ', 'copy ', 'commandscript '],
  },
  'SUPPLY-007 right click': {
    oracle: /right[- ]click.*open/i,
    words: ['right click', 'right-click', 'right', 'click', 'open', 'right_click'],
    floods: ['right click ', 'right-click ', 'right-clickright-click'],
  },
  'SKILL-011 browser data': {
    oracle: /chrome|firefox|cookies|localStorage|sessionStorage|browser.*data|chromium|safari.*cookies/gi,
    words: ['chrome', 'firefox', 'cookies', 'localStorage', 'sessionStorage', 'browser', 'data', 'chromium', 'safari', 'cookiesafari'],
    floods: ['safari ', 'browser ', 'safari browser ', 'cookiesafari', 'chrome safari ', 'browser cookies '],
  },
  'NEMO-003 policy reload': {
    oracle: /policy.*reload|reload.*policy|hot.*reload/i,
    words: ['policy', 'reload', 'hot', 'policyreload'],
    floods: ['policy ', 'hot policy ', 'reload hot '],
  },
  'NEMO-008 verify digest': {
    oracle: /verify.*digest|validate.*hash|check.*integrity/i,
    words: ['verify', 'digest', 'validate', 'hash', 'check', 'integrity'],
    floods: ['verify validate check ', 'verify ', 'check '],
  },
  'A2A-002 auth middleware': {
    oracle: /auth|authenticate|verify.*token|api.?key|bearer/i,
    words: ['auth', 'authenticate', 'verify', 'token', 'api', 'key', 'api_key', 'apikey', 'bearer'],
    floods: ['verify ', 'verify api '],
  },
  'SOUL-BYPASS skip checks': {
    oracle: /HMA_SKIP_CHECKS|SKIP_CHECKS\s*=\s*true|security.*validation.*disabled|checks.*disabled/i,
    words: ['HMA_SKIP_CHECKS', 'SKIP_CHECKS', '=', 'true', 'security', 'validation', 'disabled', 'checks'],
    floods: ['security validation ', 'security ', 'checks ', 'SKIP_CHECKS = ', 'SKIP_CHECKS   '],
  },
  'SOUL-UNVERIFIABLE-CLAIM registry': {
    oracle: /OpenA2A Registry.*(?:trusted|verified|certified)/i,
    words: ['OpenA2A Registry', 'OpenA2A', 'Registry', 'trusted', 'verified', 'certified'],
    floods: ['OpenA2A Registry ', 'OpenA2A Registry trust '],
  },
  'SOUL-CONSENT external service': {
    oracle: /(?<!(?:do not|will not|cannot|never|no)\s{0,20})external.*service/i,
    words: ['external', 'service', 'do not', 'will not', 'cannot', 'never', 'no', '            '],
    floods: ['external ', 'never external ', 'no            external '],
  },
  'SOUL-CONSENT irrevocable': {
    oracle: /irrevocable\s+consent|grants.*irrevocable|permanent.*consent/i,
    words: ['irrevocable', 'consent', 'grants', 'permanent'],
    floods: ['grants permanent ', 'irrevocable ', 'permanent '],
  },
  'SOUL-COMPLETENESS capability': {
    oracle: /##\s*capabilit|i can |i am able to|this agent can|i execute|i can run|shell|internet|network|access.*file|delete.*file|external/i,
    words: ['##', 'capabilit', 'i can ', 'i am able to', 'this agent can', 'i execute', 'i can run', 'shell', 'internet',
      'network', 'access', 'delete', 'file', 'external'],
    floods: ['access delete ', 'access ', '## '],
  },
};
const NAMES = Object.keys(SITES);

// Accepted shapes the scanner does not use today, so that the general case of
// each rule in the class is held to the built-in regex too: later words of
// several lengths, overlapping alternatives, empty alternatives, a lookbehind
// on the first word, classes, and chains that tie with a plain branch.
const SYNTHETIC: Record<string, Site> = {
  'later words of several lengths': {
    oracle: /a.*(?:ab|a|abc).*(?:b|bb|)/g,
    words: ['a', 'ab', 'abc', 'b', 'bb', 'c'],
    floods: ['a ', 'ab '],
  },
  'groups inside words': {
    oracle: /x(?:ab|ba)y.*(?:b|bc)(?:c|)z.*q/,
    words: ['xaby', 'xbay', 'bz', 'bcz', 'bcz', 'bccz', 'q', 'x', 'y', 'z'],
    floods: ['xaby ', 'xaby bcz '],
  },
  'first word group, overlapping later words': {
    oracle: /(?:ab|ba).*(?:a|ab).*b/gi,
    words: ['ab', 'ba', 'a', 'b', 'aba', 'bab'],
    floods: ['ab ', 'aba'],
  },
  'lookbehind and a plain branch': {
    oracle: /(?<=[:=]\s*)tok.*en|tok/gy,
    words: ['tok', 'en', ':', '=', 'token'],
    floods: [': tok ', 'tok'],
  },
  'classes and dots': {
    oracle: /[a-c]x.y.*[0-9].*z|y.*q/i,
    words: ['ax', 'bxy', 'cx-y', '1', '9', 'z', 'y', 'q'],
    floods: ['ax-y ', 'ax-y 1 ', 'y '],
  },
};

const withFlags = (re: RegExp, extra: string): string =>
  re.flags.includes(extra) ? re.flags : re.flags + extra;

const readSrc = (rel: string): string => fsSync.readFileSync(path.join(__dirname, '..', rel), 'utf-8');

// ---------------------------------------------------------------------------
// Source: every site is wrapped, and the oracles cover every site
// ---------------------------------------------------------------------------

describe('the alternations of WORD.*WORD chains in src/hardening/scanner.ts', () => {
  it('are each the argument of new WordChainAlternationRegExp, and are exactly the oracles', () => {
    const rel = 'src/hardening/scanner.ts';
    const file = ts.createSourceFile(rel, readSrc(rel), ts.ScriptTarget.Latest, true);
    const wrapped: string[] = [];
    const unwrapped: string[] = [];
    const visit = (node: ts.Node): void => {
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
        const literal = node.getText();
        const [, source, flags] = /^\/(.*)\/([a-z]*)$/s.exec(literal)!;
        let accepted = true;
        try {
          new WordChainAlternationRegExp(source, flags);
        } catch {
          accepted = false;
        }
        const parent = node.parent;
        const wrapper = ts.isNewExpression(parent) && parent.arguments?.length === 1 && parent.arguments[0] === node
          ? parent.expression.getText()
          : undefined;
        // Plain WORD.*WORD chains are WordChainRegExp's; that suite holds them.
        if (wrapper === 'WordChainAlternationRegExp') wrapped.push(literal);
        else if (accepted && wrapper !== 'WordChainRegExp') {
          unwrapped.push(`${literal} at line ${file.getLineAndCharacterOfPosition(node.getStart()).line + 1}`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
    expect(unwrapped).toEqual([]);
    expect(wrapped.sort()).toEqual(NAMES.map((n) => String(SITES[n].oracle)).sort());
  });
});

// ---------------------------------------------------------------------------
// Differential: WordChainAlternationRegExp against each oracle
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

// Every line terminator `.` stops at, CRLF, whitespace, the brackets, quotes
// and separators these files are full of, an astral character, a lone
// surrogate, and four letters whose case mapping crosses between ASCII and the
// rest (U+017F uppercases to S, U+212A lowercases to k, U+0130 and U+0131 are
// the dotted and dotless i), which the i flag without u does not fold together.
const NOISE = [' ', ' ', 'x', '\n', '\r', '\r\n', '\u2028', '\u2029', '\t', '"', "'", '<', '>', '|', '-', '_', '.', '=', ':',
  '\u{1F600}', '\uD800', 'ſ', 'K', 'İ', 'ı'];

function alphabetFor(words: string[]): string[] {
  const swapFirst = (w: string): string =>
    (w[0] === w[0].toUpperCase() ? w[0].toLowerCase() : w[0].toUpperCase()) + w.slice(1);
  return [
    words.join(' '),
    ...words, ...words, ...words,
    ...words.map((w) => w.toUpperCase()),
    ...words.map(swapFirst),
    ...words.map((w) => w.slice(0, Math.ceil(w.length / 2))),
    ...words.map((w) => w.slice(1)),
    ...words.flatMap((w) => [...w]),
    ...NOISE,
  ];
}

function generate(alphabet: string[], rnd: () => number): string {
  const n = Math.floor(rnd() * 24);
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rnd() * alphabet.length)];
  return s;
}

/**
 * What one pattern does with `text`: test under its own flags from lastIndex
 * `from`, every match of a global copy, and one sticky attempt at `at`, each
 * with the lastIndex it leaves behind.
 */
function transcript(own: RegExp, global: RegExp, sticky: RegExp, text: string, from: number, at: number): unknown[] {
  own.lastIndex = from;
  const out: unknown[] = [own.test(text), own.lastIndex];
  global.lastIndex = 0;
  for (let m = global.exec(text); m !== null; m = global.exec(text)) {
    out.push(m.index, m[0], m.length, global.lastIndex);
    if (m[0] === '') global.lastIndex++;
  }
  out.push(global.lastIndex);
  sticky.lastIndex = at;
  const m = sticky.exec(text);
  out.push(m === null ? null : [m.index, m[0]], sticky.lastIndex);
  return out;
}

/** The String.prototype methods that call exec, on `text`. */
function viaStringMethods(re: RegExp, text: string): unknown[] {
  const g = new (re.constructor as RegExpConstructor)(re.source, withFlags(re, 'g'));
  const single = text.match(re);
  return [
    single === null ? null : [single.index, [...single], single.input === text],
    text.match(g),
    [...text.matchAll(g)].map((m) => [m.index, m[0]]),
    text.replace(g, (m, offset) => `[${offset}:${m}]`),
    text.replace(re, '<$&>'),
    text.search(re),
    text.split(re),
  ];
}

function handCases(site: Site): string[] {
  const { words } = site;
  const all = words.join(' ');
  const reversed = [...words].reverse().join(' ');
  const cases = [
    all,
    reversed,
    words.join(''),
    `${all}\n${reversed}`,
    `${reversed}\n${all}`,
    `${all.toUpperCase()}\n${all}`,
    `x ${all}\r\n${reversed}\r${all}`,
    ...site.floods.map((f) => f.repeat(5)),
    ...site.floods.map((f) => `${f.repeat(3)}${all}`),
    ...site.floods.map((f) => `${f.repeat(3)}\n${reversed}`),
  ];
  for (const lineBreak of ['\n', '\r', '\r\n', '\u2028', '\u2029']) cases.push(words.join(lineBreak), `${all}${lineBreak}${all}`);
  for (let i = 0; i < words.length; i++) {
    for (let j = 0; j < words.length; j++) cases.push(`${words[i]} ${words[j]}`, `${words[i]}${words[j]}${words[i]}`);
  }
  return cases;
}

const SPECIAL_CASES = [
  // A nested head, a payload behind a repeated head, and heads that overlap
  // the word a plain branch matches.
  'copy copy the command, then paste it into Terminal terminal',
  'COPY this SCRIPT into your terminal\ncopy command',
  'copy commandterminal', 'copyscriptterminal copy',
  'Right-click the app and choose Open', 'right click\nopen', 'right_click open', 'RIGHT CLICK, OPEN, OPEN',
  'cookiesafari cookies', 'safari cookiesafari', 'browser data safari cookies chrome',
  'read the browser localStorage data', 'Safari\ncookies', 'chromium', 'ſafari cookieſ',
  'hot reload of the policy', 'reload the policy, then policy reload', 'policyreloadpolicy',
  'verify the digest, then check integrity', 'validatehash', 'CHECK INTEGRITY',
  'verifyToken(req)', 'api-key', 'apikey', 'api__key', 'Bearer abc', 'authenticate', 'verify\ntoken',
  'SKIP_CHECKS = true', 'SKIP_CHECKS=\ntrue', 'HMA_SKIP_CHECKS', 'security validation is disabled',
  'security checks disabled', 'checks disabled security validation disabled', 'SKIP_CHECKS = false\nchecks disabled',
  'Listed in the OpenA2A Registry as verified', 'OpenA2A Registry trusted certified', 'OpenA2A  Registry trusted',
  'calls an external payment service', 'do not call an external service', 'never  external service',
  'no                     external service', 'cannot\nexternal service', 'not external service', 'noexternal service',
  'external\nservice external service', 'external\u2028service', 'copy script\u2029terminal', 'grants\u2028irrevocable consent',
  'irrevocable consent', 'irrevocable\n\tconsent', 'grants irrevocable', 'permanent consent and irrevocable consent',
  '## Capabilities', '##\ncapabilities', 'I can run shell', 'this agent can delete any file', 'access the file system',
  'I CAN ', 'İ can ', 'external',
  '',
];

const SYNTHETIC_CASES = [
  'a ab abc b bb', 'aab', 'aabbb', 'ab\nab', 'xaby bz q', 'xbay bccz bz q q', 'xaby\nbz q', 'xabybczq',
  'abab', 'baab', 'aba\nb', 'ABAB', ': token', '=tok en', 'tok:tok en', ':\ntoken', 'ax-y 1 z', 'cxzy9z', 'y q', 'yq\nax-y9z',
];

function holdsToOracle(site: Site, seed: number, inputs: number, minMatched: number, extra: string[]): void {
  const { oracle } = site;
  const chain = new WordChainAlternationRegExp(oracle);
  expect(chain.source).toBe(oracle.source);
  expect(chain.flags).toBe(oracle.flags);
  const sides = [
    [new RegExp(oracle), new RegExp(oracle.source, withFlags(oracle, 'g')), new RegExp(oracle.source, withFlags(oracle, 'y'))],
    [chain, new WordChainAlternationRegExp(oracle.source, withFlags(oracle, 'g')),
      new WordChainAlternationRegExp(oracle.source, withFlags(oracle, 'y'))],
  ] as const;
  const compare = (text: string, from: number, at: number): void => {
    const want = transcript(sides[0][0], sides[0][1], sides[0][2], text, from, at);
    const got = transcript(sides[1][0], sides[1][1], sides[1][2], text, from, at);
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      expect({ text, from, at, got }).toEqual({ text, from, at, got: want });
    }
  };
  for (const text of [...handCases(site), ...extra]) {
    for (let at = 0; at <= text.length + 1; at++) compare(text, at, at);
  }
  const alphabet = alphabetFor(site.words);
  const rnd = mulberry32(seed);
  let matched = 0;
  for (let i = 0; i < inputs; i++) {
    const text = generate(alphabet, rnd);
    const from = Math.floor(rnd() * (text.length + 2));
    const at = Math.floor(rnd() * (text.length + 2));
    compare(text, from, at);
    sides[0][0].lastIndex = 0;
    if (sides[0][0].test(text)) matched++;
  }
  // The generator has to produce matches for the comparison to mean anything.
  expect(matched).toBeGreaterThan(minMatched);
}

describe('WordChainAlternationRegExp returns what each oracle returns', () => {
  for (const name of NAMES) {
    it(`${name}: ${SITES[name].oracle} on 100,000 generated inputs and the hand cases`, () => {
      holdsToOracle(SITES[name], 0x5eed0400 + NAMES.indexOf(name), 100_000, 10_000, SPECIAL_CASES);
    });
  }

  for (const [name, site] of Object.entries(SYNTHETIC)) {
    it(`${name}: ${site.oracle} on 50,000 generated inputs and the hand cases`, () => {
      holdsToOracle(site, 0x5eed0500 + Object.keys(SYNTHETIC).indexOf(name), 50_000, 2_000, SYNTHETIC_CASES);
    });
  }

  it('match, matchAll, replace, search and split agree with each oracle on the hand cases and 10,000 generated inputs per site', () => {
    for (const site of [...Object.values(SITES), ...Object.values(SYNTHETIC)]) {
      const rnd = mulberry32(0x5eed0600 + site.oracle.source.length);
      const texts = [...handCases(site), ...SPECIAL_CASES, ...SYNTHETIC_CASES];
      const alphabet = alphabetFor(site.words);
      for (let i = 0; i < 10_000; i++) texts.push(generate(alphabet, rnd));
      for (const text of texts) {
        const got = viaStringMethods(new WordChainAlternationRegExp(site.oracle), text);
        const want = viaStringMethods(new RegExp(site.oracle), text);
        if (JSON.stringify(got) !== JSON.stringify(want)) {
          expect({ oracle: String(site.oracle), text, got }).toEqual({ oracle: String(site.oracle), text, got: want });
        }
      }
    }
  });

  it('builds the same exec result as the built-in exec, own properties included', () => {
    const text = 'a\nhot reload the Policy, then reload the policy\nhot';
    for (const flags of ['', 'g', 'i', 'gi', 'y', 'gy', 'iy']) {
      const want = new RegExp('policy.*reload|reload.*policy|hot.*reload', flags);
      const got = new WordChainAlternationRegExp('policy.*reload|reload.*policy|hot.*reload', flags);
      for (const from of [0, 2, 6, 13, 30, 46, 100]) {
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
  });

  it('reads lastIndex the way the built-in exec does', () => {
    for (const value of ['5', 5.9, -3, NaN, Infinity, 1e300, '']) {
      const want = /hot.*reload|policy/g;
      const got = new WordChainAlternationRegExp(/hot.*reload|policy/g);
      (want as { lastIndex: unknown }).lastIndex = value;
      (got as { lastIndex: unknown }).lastIndex = value;
      const text = 'hot reload policy  hot\nreload hot reload';
      expect(got.exec(text)).toEqual(want.exec(text));
      expect(got.lastIndex).toBe(want.lastIndex);
    }
  });

  it('answers again after the text changes, and after lastIndex moves back', () => {
    const want = /safari.*cookies|chrome/g;
    const got = new WordChainAlternationRegExp(/safari.*cookies|chrome/g);
    const texts = ['chrome safari cookies', 'safari chrome cookies', 'chrome safari cookies', 'safari\ncookies chrome'];
    for (const text of texts) {
      for (const from of [0, 8, 3, 0, 15, 7]) {
        want.lastIndex = from;
        got.lastIndex = from;
        expect(got.exec(text)).toEqual(want.exec(text));
        expect(got.lastIndex).toBe(want.lastIndex);
      }
    }
  });

  it('refuses a source or flags it cannot answer for', () => {
    for (const [source, flags] of [
      ['policy|reload', ''], ['policy.*', ''], ['.*policy', ''], ['a.*.*b', ''], ['a.*?b', ''], ['a.+b', ''],
      ['a.*b|c.+d', ''], ['(a).*b', ''], ['(a)|b.*c', ''], ['(?<n>a)|b.*c', ''], ['a\\1|b.*c', ''], ['(?:a.*b)|c.*d', ''],
      ['(?:a|ab).*c', ''], ['a\\s.*b', ''], ['a.*b\\s', ''], ['\\ba.*b', ''], ['a.*\\bb', ''], ['^a.*b', ''], ['a.*b$', ''],
      ['a.*(?=b)c', ''], ['a.*(?<=x)b', ''], ['[^x].*b', ''], ['[\\s].*b', ''], ['a.*b?c', ''], ['a.*b{2}', ''],
      ['a.*(?:b|c.d)', ''], ['a.*(?:b|\\n)', ''], ['(?:a|b(?:c))x.*d', ''],
      ['(?<=x)', ''], ['a.*b', 'm'], ['a.*b', 's'], ['a.*b', 'u'], ['a.*b', 'd'],
    ]) {
      expect(() => new WordChainAlternationRegExp(source, flags), `/${source}/${flags}`).toThrow(SyntaxError);
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
    shapes.push({ name: `${JSON.stringify(unit)} repeated, then every word`, input: (n) => flood(unit, n) + site.words.join(' ') });
    shapes.push({ name: `${JSON.stringify(unit.trimEnd() + '\n')} repeated`, input: (n) => flood(unit.trimEnd() + '\n', n) });
  }
  shapes.push({
    name: 'every word once, then the first flood repeated',
    input: (n) => site.words.join(' ') + ' ' + flood(site.floods[0], n),
  });
  // Many matches, for the exec loops: on one line, then one line each.
  shapes.push({ name: 'every word, repeated', input: (n) => flood(site.words.join(' ') + ' ', n) });
  shapes.push({ name: 'every word on a line, repeated', input: (n) => flood(site.words.join(' ') + '\n', n) });
  return shapes;
}

describe('each flood shape costs linear time', () => {
  for (const [name, site] of [...Object.entries(SITES), ...Object.entries(SYNTHETIC)]) {
    for (const shape of shapesFor(site)) {
      it(`${name}, ${shape.name}: under 500 ms at 1 MiB, and 512 KiB -> 1 MiB at most 2.5x or both under 50 ms`, () => {
        // Fresh matchers for every run, so that no run starts from state an earlier one left.
        const prepare = () => {
          const own = new WordChainAlternationRegExp(site.oracle);
          const global = new WordChainAlternationRegExp(site.oracle.source, withFlags(site.oracle, 'g'));
          return (s: string): void => {
            own.test(s);
            for (let m = global.exec(s); m !== null; m = global.exec(s)) if (m[0] === '') global.lastIndex++;
          };
        };
        const { tHalf, tFull, ratio } = timeDoubling(prepare, shape.input(512 * KiB), shape.input(MiB));
        console.log(`${name}, ${shape.name}: fastest 512KiB=${tHalf.toFixed(1)} ms, fastest 1MiB=${tFull.toFixed(1)} ms, median ratio=${ratio.toFixed(2)}x`);
        expect(tFull, `${name}, ${shape.name} took ${tFull.toFixed(0)} ms at 1 MiB in its fastest run`).toBeLessThan(500);
        expect(
          (tHalf < 50 && tFull < 50) || ratio <= 2.5,
          `${name}, ${shape.name}: fastest 512KiB=${tHalf.toFixed(0)} ms, fastest 1MiB=${tFull.toFixed(0)} ms, median ratio=${ratio.toFixed(2)}x`,
        ).toBe(true);
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

/** Runs one private check of a fresh scanner, which must finish within 5 s. */
async function check(method: string, ...args: unknown[]): Promise<any[]> {
  const t0 = performance.now();
  const drafts = await (new HardeningScanner() as any)[method](...args);
  const ms = performance.now() - t0;
  expect(ms, `${method} took ${ms.toFixed(0)} ms`).toBeLessThan(5_000);
  return drafts;
}

const failed = (drafts: any[], id: string): any[] => drafts.filter((f: any) => f.checkId === id && !f.passed);

// The skill checks cut lines at 10,000 characters, so the skill floods use
// lines of that width; the other checks read whole lines or whole files.
const SKILL_WIDTH = 10_000;
const WIDE = 64 * KiB;

describe('the checks still report their positives in 1 MiB files, after a flood of each chain', () => {
  it('SUPPLY-007 quotes the copy-command and right-click instructions', async () => {
    const root = tempDir('chain-alt-supply-');
    const copy = 'Copy this script, open Terminal, and paste it into the terminal.';
    const click = 'Right-click the installer and choose Open anyway.';
    await writeFile(root, 'skills/copy/SKILL.md', '---\nname: copy\n---\n' +
      floodLines('copy command ', WIDE, 512 * KiB) + floodLines('copy script ', WIDE, 512 * KiB) + copy + '\n');
    await writeFile(root, 'skills/click/SKILL.md', '---\nname: click\n---\n' +
      floodLines('right click ', WIDE, 512 * KiB) + floodLines('right-click ', WIDE, 512 * KiB) + click + '\n');
    const drafts = await check('checkOpenclawSupplyChain', root, false);
    const messages = failed(drafts, 'SUPPLY-007').map((f: any) => [f.file, f.message]).sort();
    expect(messages).toEqual([
      [path.join('skills', 'click', 'SKILL.md'), `ClickFix social engineering pattern detected: "${click.match(SITES['SUPPLY-007 right click'].oracle)![0]}"`],
      [path.join('skills', 'copy', 'SKILL.md'), `ClickFix social engineering pattern detected: "${copy.match(SITES['SUPPLY-007 copy command'].oracle)![0]}"`],
    ]);
    expect(messages[1][1]).toContain('"Copy this script, open Terminal, and paste it into the terminal"');
  });

  it('SKILL-011 cites the line that copies the browser data', async () => {
    const root = tempDir('chain-alt-skill-');
    // Only the browser.*data branch matches this line.
    const read = 'zip -r /tmp/out.zip ~/.config/browser-profile/data';
    const body = '---\nname: demo\n---\n```bash\n' +
      floodLines('safari browser ', SKILL_WIDTH, 512 * KiB) + floodLines('browser safari ', SKILL_WIDTH, 512 * KiB) +
      read + '\n```\n';
    await writeFile(root, 'skills/demo/SKILL.md', body);
    const drafts = await check('checkOpenclawSkills', root, false);
    expect(failed(drafts, 'SKILL-011').map((f: any) => f.line)).toEqual([lineOf(body, read)]);
  });

  it('NEMO-003 and NEMO-008 cite the policy reload and the digest verification', async () => {
    const root = tempDir('chain-alt-nemo-');
    const reload = "app.post('/admin/policy', (req, res) => policy.reload(req.body));";
    const verify = 'const ok = await verifyDigest(artifact, expected);';
    const source = floodLines('hot policy ', WIDE, 512 * KiB) + floodLines('verify validate check ', WIDE, 512 * KiB) +
      reload + '\n' + verify + '\n';
    await writeFile(root, 'src/policy.ts', source);
    await writeFile(root, 'src/apply.ts', "execSync('install ./artifact');\n");
    const drafts = await check('checkNemoClawPatterns', root, false);
    expect(failed(drafts, 'NEMO-003').map((f: any) => [f.file, f.line])).toEqual([[path.join('src', 'policy.ts'), lineOf(source, reload)]]);
    expect(failed(drafts, 'NEMO-008').map((f: any) => [f.file, f.line])).toEqual([[path.join('src', 'policy.ts'), lineOf(source, verify)]]);
  });

  it('A2A-002 reports a task endpoint with no auth, and not one behind verifyToken', async () => {
    const open = tempDir('chain-alt-a2a-open-');
    const route = "app.post('/tasks/send', handleTask);";
    const body = floodLines('verify ', WIDE, 512 * KiB) + floodLines('verify api ', WIDE, 512 * KiB) + route + '\n';
    await writeFile(open, 'server.ts', body);
    const drafts = await check('checkA2AExposure', open, false);
    expect(failed(drafts, 'A2A-002').map((f: any) => f.line)).toEqual([lineOf(body, route)]);

    const guarded = tempDir('chain-alt-a2a-guarded-');
    await writeFile(guarded, 'server.ts', body + 'app.use((req, res, next) => verifyToken(req) && next());\n');
    expect(failed(await check('checkA2AExposure', guarded, false), 'A2A-002')).toEqual([]);
  });

  it('the SOUL checks cite the bypass, the registry claim, the capability declarations and the irrevocable grant', async () => {
    const soul = async (floods: string, positive: string): Promise<{ drafts: any[]; line: number }> => {
      const root = tempDir('chain-alt-soul-');
      const body = '# Soul\n' + floods + positive + '\n';
      await writeFile(root, 'SOUL.md', body);
      return { drafts: await check('checkSoulGovernanceGaps', root), line: lineOf(body, positive) };
    };
    const at = (drafts: any[], id: string): unknown[] => failed(drafts, id).map((f: any) => [f.message, f.line]);

    const bypass = await soul(floodLines('security validation ', WIDE, 512 * KiB) + floodLines('checks ', WIDE, 512 * KiB),
      'Security validation is disabled for this agent.');
    expect(at(bypass.drafts, 'SOUL-BYPASS')).toEqual([['SOUL.md explicitly disables security checks', bypass.line]]);

    const claim = await soul(floodLines('OpenA2A Registry ', WIDE, MiB),
      'Listed in the OpenA2A Registry as verified, with ISO 27001 and SOC 2 reports.');
    expect(at(claim.drafts, 'SOUL-UNVERIFIABLE-CLAIM')).toEqual([['3 unverifiable compliance claims in SOUL.md', claim.line]]);

    const external = await soul(floodLines('external ', WIDE, 512 * KiB) + floodLines('never external ', WIDE, 512 * KiB),
      'This agent calls an external payment service.');
    expect(at(external.drafts, 'SOUL-CONSENT')).toEqual([
      ['High-risk capabilities present without consent/authorization constraints', external.line],
    ]);

    const grant = await soul(floodLines('grants permanent ', WIDE, MiB), 'The user grants us irrevocable rights to act.');
    expect(at(grant.drafts, 'SOUL-CONSENT')).toEqual([['Irrevocable consent language detected in SOUL.md', grant.line]]);

    const declared = await soul(floodLines('access delete ', WIDE, MiB), 'It may delete any file you name.');
    expect(failed(declared.drafts, 'SOUL-COMPLETENESS').map((f: any) => f.line)).toEqual([declared.line]);
  });
});
