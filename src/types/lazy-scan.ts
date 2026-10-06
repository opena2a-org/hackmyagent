/**
 * Linear-time drivers for patterns that a scanned file can flood with openers.
 *
 * A lazy body (or a greedy run such as `[^>]+` or `\S+`) that never meets its
 * closer scans to the end of the input, and a regex retries that scan from
 * every later opener, so N openers with no closer cost O(N * n). The scanned
 * bytes come from the party being scanned, which makes that a way to stall a
 * scan.
 *
 * Each driver here returns exactly what its pattern returns: the same matches,
 * at the same offsets, with the same captures. None bounds the body or stops it
 * at the next opener. An HTML comment may contain `<!--`, a script element may
 * contain `<script` and spans nest, so either bound would let one added token
 * hide content the pattern matches today. The drivers rely on one property
 * instead: once a match attempt fails because no closer follows, no attempt
 * further right can succeed, so the search can stop. The differential tests
 * in `__tests__/lazy-regex-sibling-sites.test.ts` hold each driver to its
 * pattern.
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
