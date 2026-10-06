/**
 * Linear-time drivers for patterns that a scanned file can flood with openers.
 *
 * A lazy body (or a greedy run such as `[^>]+`, `\S+` or `.*`) that never
 * meets its closer scans to the end of the input, and a regex retries that
 * scan from every later opener, so N openers with no closer cost O(N * n).
 * The scanned bytes come from the party being scanned, which makes that a way
 * to stall a scan.
 *
 * Each driver here returns exactly what its pattern returns: the same matches,
 * at the same offsets, with the same captures. None bounds the body or stops it
 * at the next opener. An HTML comment may contain `<!--`, a script element may
 * contain `<script` and spans nest, so either bound would let one added token
 * hide content the pattern matches today. The drivers rely on one property
 * instead: once a match attempt fails because no closer follows, no attempt
 * further right can succeed, so the search can stop. The differential tests
 * in `__tests__/lazy-regex-sibling-sites.test.ts` and
 * `__tests__/lazy-regex-word-chains.test.ts` hold each driver to its pattern.
 */

export interface HtmlComment {
  /** Offset of `<!--`. */
  index: number;
  /** Offset just past `-->`. */
  end: number;
  /** Text between `<!--` and `-->`, untrimmed. */
  body: string;
}

/**
 * The matches of `/<!--([\s\S]*?)-->/g`, with `body` as capture 1.
 *
 * The same spans are the matches of `/<!--\s*([\s\S]*?)\s*-->/g`; that
 * pattern's capture is `body.trim()`, since `\s` and `String.prototype.trim`
 * cover the same characters.
 */
export function* htmlComments(text: string): Generator<HtmlComment> {
  let from = 0;
  for (;;) {
    const open = text.indexOf('<!--', from);
    if (open < 0) return;
    const close = text.indexOf('-->', open + 4);
    // Every later opener would need a closer after this point too.
    if (close < 0) return;
    yield { index: open, end: close + 3, body: text.slice(open + 4, close) };
    from = close + 3;
  }
}

/** Offsets of the last match of a global `closer`, or undefined. */
function lastMatch(text: string, closer: RegExp): { start: number; end: number } | undefined {
  let last: { start: number; end: number } | undefined;
  closer.lastIndex = 0;
  for (let m = closer.exec(text); m !== null; m = closer.exec(text)) {
    last = { start: m.index, end: m.index + m[0].length };
  }
  return last;
}

/**
 * `text.replace(pattern, replacement)` for a global `pattern` whose every match
 * ends with a match of `closer` (also global). No match can end past the last
 * closer, so the pattern only runs on the text up to it.
 */
export function replaceBeforeLastCloser(
  text: string,
  pattern: RegExp,
  closer: RegExp,
  replacement: string,
): string {
  const last = lastMatch(text, closer);
  if (!last) return text;
  return text.slice(0, last.end).replace(pattern, replacement) + text.slice(last.end);
}

/**
 * The matches of an element pattern shaped `<tag[^>]*REST>([\s\S]*?)</tag>`,
 * as a global exec loop would return them.
 *
 * `element` is that pattern with the sticky flag; `opener` (global) matches
 * `<tag` and `closer` (global) matches `</tag>`. REST must not depend on where
 * the opener sits, and must end its start tag at or after the first `>` that
 * follows the opener.
 *
 * Two facts keep the work linear. No match can end past the last closer, so
 * only the text up to it is searched. And the openers inside one `>`-free run
 * all reach the same positions through `[^>]*`, a later one fewer of them, so
 * when the first opener of a run fails the rest of the run does too and the
 * search resumes after that `>`. A start tag that ends at or after the last
 * closer leaves no closer for the body, so the search stops there.
 */
export function* elementMatches(
  text: string,
  element: RegExp,
  opener: RegExp,
  closer: RegExp,
): Generator<RegExpExecArray> {
  const last = lastMatch(text, closer);
  if (!last) return;
  const prefix = text.slice(0, last.end);
  let from = 0;
  for (;;) {
    opener.lastIndex = from;
    const open = opener.exec(prefix);
    if (open === null) return;
    const tagEnd = prefix.indexOf('>', open.index + open[0].length);
    if (tagEnd < 0 || tagEnd >= last.start) return;
    element.lastIndex = open.index;
    const m = element.exec(prefix);
    if (m !== null) {
      yield m;
      from = element.lastIndex;
    } else {
      from = tagEnd + 1;
    }
  }
}

/**
 * The match of `/<!--[\s\S]*?soul:profile=([^>]*?)\s*-->/i`, or null.
 *
 * The value runs from after `soul:profile=` to the first `>`, which must close
 * a `-->`; trailing whitespace before the `-->` is not part of it. The lazy
 * gap before `soul:profile=` crosses anything, including `-->`, so the first
 * `<!--` in the text is the start of the match whenever there is one.
 */
export function permissiveProfileMarker(
  text: string,
): { index: number; end: number; value: string } | null {
  const open = text.indexOf('<!--');
  if (open < 0) return null;
  const key = /soul:profile=/gi;
  key.lastIndex = open + 4;
  for (let m = key.exec(text); m !== null; m = key.exec(text)) {
    const valueStart = m.index + m[0].length;
    const gt = text.indexOf('>', valueStart);
    if (gt < 0) return null;
    if (gt - 2 >= valueStart && text.startsWith('-->', gt - 2)) {
      return { index: open, end: gt + 1, value: text.slice(valueStart, gt - 2).trimEnd() };
    }
    // Every `soul:profile=` before this `>` meets the same `>` and fails the
    // same way; none can straddle it, since the key has no `>`.
    key.lastIndex = gt + 1;
  }
  return null;
}

/**
 * `text.match(/<!--\s*soul:profile=(\S+)\s*-->/i)`.
 *
 * From a `<!--` whose key is present, the value is the run of non-whitespace
 * after `soul:profile=`, and the match needs a `-->` inside that run or after
 * the whitespace that ends it. When a `<!--` fails, every later `<!--` inside
 * the same run fails too, since it reaches the same run end with a shorter
 * value. The search therefore resumes at the last place a `<!--` can still end
 * where whitespace begins, instead of rescanning the run from each one.
 */
export function strictProfileMarker(text: string): RegExpExecArray | null {
  const marker = /<!--\s*soul:profile=(\S+)\s*-->/iy;
  const key = /\s*soul:profile=\S*/iy;
  for (let open = text.indexOf('<!--'); open >= 0; ) {
    marker.lastIndex = open;
    const m = marker.exec(text);
    if (m !== null) return m;
    key.lastIndex = open + 4;
    const next = key.exec(text) === null ? open + 1 : Math.max(open + 1, key.lastIndex - 4);
    open = text.indexOf('<!--', next);
  }
  return null;
}

/**
 * The matches of `/(?:eval|Function)\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/g`.
 *
 * `call` is that pattern with the sticky flag. A call whose quote is never
 * again followed by optional whitespace and `)` cannot match, and neither can
 * any later call with the same quote, so those are skipped without running
 * the lazy body to the end of the text.
 */
export function* quotedCallMatches(text: string, call: RegExp): Generator<RegExpExecArray> {
  const lastCloser = new Map<string, number>();
  const closer = /(['"`])\s*\)/g;
  for (let m = closer.exec(text); m !== null; m = closer.exec(text)) lastCloser.set(m[1], m.index);
  if (lastCloser.size === 0) return;
  const opener = /(?:eval|Function)\s*\(\s*(['"`])/g;
  for (let open = opener.exec(text); open !== null; open = opener.exec(text)) {
    const quoteAt = open.index + open[0].length - 1;
    if ((lastCloser.get(open[1]) ?? -1) > quoteAt) {
      call.lastIndex = open.index;
      const m = call.exec(text);
      if (m !== null) {
        yield m;
        opener.lastIndex = call.lastIndex;
        continue;
      }
    }
    opener.lastIndex = open.index + 1;
  }
}

export interface TagAttributeSpec {
  /** Global; matches the tag's opener, such as `<meta`. */
  opener: RegExp;
  /** Global, optional; an attribute that must come before the captured one. */
  key?: RegExp;
  /** Global; the captured attribute's name through its opening quote. */
  attribute: RegExp;
  /** Fewest characters the quoted value may have. */
  minLength: number;
}

export interface TagAttribute {
  /** Offset of the opener. */
  index: number;
  /** Offset just past the `>` that ends the match. */
  end: number;
  /** The quoted value, capture 1. */
  value: string;
}

/**
 * The matches of a global pattern shaped
 * `OPENER[^>]*KEY[^>]*ATTRIBUTE([^"]{MIN,})"[^>]*\/?>` (or without
 * `KEY[^>]*`), as an exec loop would return them.
 *
 * OPENER, KEY and ATTRIBUTE match text with no `>`, matches of KEY cannot
 * overlap one another, nor can matches of ATTRIBUTE, and ATTRIBUTE ends with
 * `"`. The value may cross a `>`.
 *
 * Whether a value succeeds depends only on where its attribute sits: its
 * quote must close at least MIN characters later, before the last `>` in the
 * text. Backtracking picks the last such attribute between the first KEY
 * after the opener and the first `>` after it, so that one is found by binary
 * search instead of re-running both `[^>]*` for every KEY. Every later opener
 * before that `>` sees a subset of the same attributes, so when the first one
 * fails the search resumes after the `>`.
 */
export function* tagAttributeMatches(text: string, spec: TagAttributeSpec): Generator<TagAttribute> {
  const lastGt = text.lastIndexOf('>');
  if (lastGt < 0) return;
  const keys: { start: number; end: number }[] = [];
  if (spec.key) {
    spec.key.lastIndex = 0;
    for (let m = spec.key.exec(text); m !== null; m = spec.key.exec(text)) {
      keys.push({ start: m.index, end: m.index + m[0].length });
    }
  }
  const values: { start: number; from: number; quote: number }[] = [];
  spec.attribute.lastIndex = 0;
  for (let m = spec.attribute.exec(text); m !== null; m = spec.attribute.exec(text)) {
    const from = m.index + m[0].length;
    const quote = text.indexOf('"', from);
    if (quote >= 0 && quote < lastGt && quote - from >= spec.minLength) values.push({ start: m.index, from, quote });
  }
  if (values.length === 0) return;
  const firstAtOrAfter = (list: { start: number }[], pos: number): number => {
    let lo = 0;
    let hi = list.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (list[mid].start < pos) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  let from = 0;
  for (;;) {
    spec.opener.lastIndex = from;
    const open = spec.opener.exec(text);
    if (open === null) return;
    const bodyStart = open.index + open[0].length;
    const gt = text.indexOf('>', bodyStart);
    if (gt < 0) return;
    let earliest: number | undefined = bodyStart;
    if (spec.key) {
      const key = keys[firstAtOrAfter(keys, bodyStart)];
      earliest = key !== undefined && key.start < gt ? key.end : undefined;
    }
    const value = earliest === undefined ? undefined : values[firstAtOrAfter(values, gt) - 1];
    if (earliest !== undefined && value !== undefined && value.start >= earliest) {
      const end = text.indexOf('>', value.quote + 1) + 1;
      yield { index: open.index, end, value: text.slice(value.from, value.quote) };
      from = end;
    } else {
      from = gt + 1;
    }
  }
}

/** A match of a pattern shaped `OPEN(BODY)CLOSE`. */
export interface Delimited {
  /** Offset of the opener. */
  index: number;
  /** Offset just past the closer. */
  end: number;
  /** Text between opener and closer, capture 1. */
  body: string;
}

/**
 * The matches of `/OPEN(.*?)CLOSE/g` for literal, case-sensitive OPEN and
 * CLOSE with no line break in them.
 *
 * `.` stops at a line break, so an opener matches up to the first closer on
 * its own line. When that closer is missing, every later opener on the line
 * misses it too, so the search resumes on the next line. The next closer and
 * the next line break are each searched for once and reused while they still
 * lie ahead, so neither search is repeated from every opener.
 */
export function* sameLineMatches(text: string, open: string, close: string): Generator<Delimited> {
  const lineBreak = /[\n\r\u2028\u2029]/g;
  let nextClose = -1;
  let nextBreak = -1;
  for (let from = 0; ; ) {
    const start = text.indexOf(open, from);
    if (start < 0) return;
    const bodyStart = start + open.length;
    if (nextClose < bodyStart) {
      nextClose = text.indexOf(close, bodyStart);
      // No later opener has a closer after it either.
      if (nextClose < 0) return;
    }
    if (nextBreak < bodyStart) {
      lineBreak.lastIndex = bodyStart;
      nextBreak = lineBreak.exec(text)?.index ?? text.length;
    }
    if (nextClose < nextBreak) {
      yield { index: start, end: nextClose + close.length, body: text.slice(bodyStart, nextClose) };
      from = nextClose + close.length;
    } else {
      from = nextBreak + 1;
    }
  }
}

/**
 * `new RegExp(words.join('.*'), 'i').test(text)`, for plain words with no
 * line break in them.
 *
 * As a regex, each `.*` runs to the end of the line and backs off one
 * character at a time to look for the next word, from every occurrence of the
 * word before it, which costs up to the cube of the line's length when the
 * last word is missing. Taking each word's first occurrence after the previous one
 * finds a match whenever there is one, and when a line has none its other
 * occurrences of the first word have none either, so each line is read once.
 */
export function wordsInOrderOnOneLine(text: string, words: readonly string[]): boolean {
  return indexOfWordsInOrderOnOneLine(text, words) >= 0;
}

/**
 * `text.search(new RegExp(words.join('.*'), 'i'))`, for plain words with no
 * line break in them: the offset of the leftmost match, or -1.
 *
 * The search is the one in wordsInOrderOnOneLine. The first line it accepts
 * is the first line holding a match, and it accepts that line from its first
 * occurrence of the first word, which is where the leftmost match starts.
 */
export function indexOfWordsInOrderOnOneLine(text: string, words: readonly string[]): number {
  const finders = words.map((w) => new RegExp(escapeRegExp(w), 'gi'));
  return wordChainSpan(text, finders, 0)?.start ?? -1;
}

const escapeRegExp = (word: string): string => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const LINE_BREAK = /[\n\r\u2028\u2029]/g;

/**
 * Where the leftmost match of `WORD.*WORD...` (two or more words) at or
 * after `from` starts and ends, or null. `finders` holds one global regex per
 * word. With `firstAt`, a sticky regex for the first word, the match must
 * start at `from`.
 *
 * The search takes the first occurrence of the first word and each later
 * word's first occurrence after the one before it, on that line. When the
 * line has no match, its later occurrences of the first word have none
 * either, so the search moves to the next line. Every `.*` is greedy, so the
 * match ends where the last occurrence of the last word on the line ends.
 */
function wordChainSpan(
  text: string,
  finders: readonly RegExp[],
  from: number,
  firstAt?: RegExp,
): { start: number; end: number } | null {
  const first = firstAt ?? finders[0];
  const last = finders[finders.length - 1];
  for (let at = from; at <= text.length; ) {
    first.lastIndex = at;
    const head = first.exec(text);
    if (head === null) return null;
    const start = head.index;
    LINE_BREAK.lastIndex = start;
    const lineEnd = LINE_BREAK.exec(text)?.index ?? text.length;
    const line = text.slice(start, lineEnd);
    let lastAt = 0;
    let pos = head[0].length;
    let k = 1;
    for (; k < finders.length; k++) {
      finders[k].lastIndex = pos;
      const m = finders[k].exec(line);
      if (m === null) break;
      lastAt = m.index;
      pos = m.index + m[0].length;
    }
    if (k === finders.length) {
      let end = pos;
      last.lastIndex = lastAt + 1;
      for (let m = last.exec(line); m !== null; m = last.exec(line)) {
        end = m.index + m[0].length;
        last.lastIndex = m.index + 1;
      }
      return { start, end: start + end };
    }
    if (firstAt) return null;
    at = lineEnd + 1;
  }
  return null;
}

/** The words of a regex source shaped `WORD.*WORD...`, or null. */
function wordChainWords(source: string): string[] | null {
  const words: string[] = [];
  let word = '';
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') {
      const escaped = source[i + 1];
      if (escaped === undefined || !/[\\/.$^*+?()[\]{}|-]/.test(escaped)) return null;
      word += escaped;
      i++;
    } else if (c === '.' && source[i + 1] === '*') {
      if (word === '') return null;
      words.push(word);
      word = '';
      i++;
    } else if ('.*+?()[]{}|^$\n\r\u2028\u2029'.includes(c)) {
      return null;
    } else {
      word += c;
    }
  }
  if (word === '' || words.length === 0) return null;
  words.push(word);
  return words;
}

function toLength(value: unknown): number {
  const n = Math.trunc(Number(value));
  return Number.isNaN(n) || n <= 0 ? 0 : Math.min(n, Number.MAX_SAFE_INTEGER);
}

/**
 * A RegExp for a pattern shaped `WORD.*WORD`, with two or more literal words
 * and no flags other than g, i and y, that returns exactly what the pattern
 * returns without running it.
 *
 * As a regex, each `.*` runs to the end of the line and backs off one
 * character at a time to look for the next word, from every occurrence of the
 * word before it. A line that repeats the first word without the last costs
 * the square of its length with two words and the cube with three. exec finds
 * the same match with wordChainSpan instead, and sets lastIndex as the
 * built-in exec does. It is the only method overridden: test, match,
 * matchAll, replace, search and split all go through it, so code that holds
 * the object as a RegExp needs no change.
 */
export class WordChainRegExp extends RegExp {
  private readonly finders: RegExp[];
  private readonly firstAt: RegExp;

  constructor(pattern: RegExp | string, flags?: string) {
    super(pattern, flags);
    const words = /^[giy]*$/.test(this.flags) ? wordChainWords(this.source) : null;
    if (words === null) {
      throw new SyntaxError(`/${this.source}/${this.flags} is not WORD.*WORD with flags from g, i and y`);
    }
    const caseFlag = this.ignoreCase ? 'i' : '';
    this.finders = words.map((w) => new RegExp(escapeRegExp(w), 'g' + caseFlag));
    this.firstAt = new RegExp(escapeRegExp(words[0]), 'y' + caseFlag);
  }

  exec(input: string): RegExpExecArray | null {
    const text = String(input);
    const advances = this.global || this.sticky;
    const from = advances ? toLength(this.lastIndex) : 0;
    const span =
      from <= text.length ? wordChainSpan(text, this.finders, from, this.sticky ? this.firstAt : undefined) : null;
    if (span === null) {
      if (advances) this.lastIndex = 0;
      return null;
    }
    if (advances) this.lastIndex = span.end;
    const match = [text.slice(span.start, span.end)] as unknown as RegExpExecArray;
    match.index = span.start;
    match.input = text;
    match.groups = undefined;
    return match;
  }
}
