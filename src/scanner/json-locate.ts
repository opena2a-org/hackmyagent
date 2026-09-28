/**
 * The line of ONE value in a JSON or JSONC document, found by following its
 * structural path — never by searching the text for the value (#379).
 *
 * A permission grant in a structured config has to be cited by structure,
 * because `allow` and `deny` hold textually identical values: a search for the
 * entry's text can land on the deny entry, and the finding then tells the reader
 * to remove the rule that stops an agent reading private keys. Three text
 * heuristics were tried and each failed (see `permission-vocabulary.ts`). This
 * is not a fourth: `walkConfigForGrants` records the keys and indices it
 * followed to the value it judged, and this module follows the SAME path
 * through the raw text.
 *
 * What makes the citation sound:
 *
 * - **Structure, not text.** Only the key at each level and the index in each
 *   array decide where to descend. Keys are compared DECODED (`"allow"` is
 *   `allow`), exactly as the parser saw them.
 * - **The parser's duplicate-key rule.** `JSON.parse` keeps the LAST value for
 *   a repeated key, so this descends into the last match too.
 * - **The value is checked.** The located token must decode to exactly the
 *   value the walker judged. Any disagreement — a document the JSONC retry
 *   rewrote, a path that no longer resolves — returns `undefined`. The failure
 *   mode is a missing line, never a different one.
 * - **One bound, one mechanism.** The path comes from the walk that found the
 *   grant, so its depth bound and visited set are the citation's own: a grant
 *   the walk never reached has no path to follow.
 *
 * Cost: each level scans the container it is in once, skipping nested values
 * without allocating, so a lookup is O(document length × path length) with
 * O(path length) memory. No per-line or per-node state is retained.
 *
 * JSONC: `//` and block comments are skipped and a trailing comma before `}` or
 * `]` is accepted, mirroring the retry in `permission-grant.ts`.
 */

export type JsonPath = ReadonlyArray<string | number>;

/**
 * The 1-indexed line on which the value at `path` starts, or `undefined` when
 * the path does not resolve or the value there is not `expected`.
 */
export function lineOfJsonValue(
  text: string,
  path: JsonPath,
  expected: string | boolean,
): number | undefined {
  // A UTF-8 BOM parses as nothing and sits on line 1, so it only moves the start.
  const start = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const at = seek(text, start, path, 0);
  if (at === undefined || !valueIs(text, at, expected)) return undefined;
  let line = 1;
  for (let i = 0; i < at; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function seek(s: string, from: number, path: JsonPath, k: number): number | undefined {
  let i = skipTrivia(s, from);
  if (k === path.length) return i;
  const seg = path[k];

  if (typeof seg === 'string') {
    if (s[i] !== '{') return undefined;
    i++;
    let match = -1;
    for (;;) {
      i = skipTrivia(s, i);
      if (s[i] === '}') break;
      if (s[i] !== '"') return undefined;
      const keyEnd = skipString(s, i);
      if (keyEnd < 0) return undefined;
      let key: unknown;
      try { key = JSON.parse(s.slice(i, keyEnd)); } catch { return undefined; }
      i = skipTrivia(s, keyEnd);
      if (s[i] !== ':') return undefined;
      i = skipTrivia(s, i + 1);
      if (key === seg) match = i; // last one wins, as in JSON.parse
      const valueEnd = skipValue(s, i);
      if (valueEnd < 0) return undefined;
      i = skipTrivia(s, valueEnd);
      if (s[i] === ',') { i++; continue; }
      if (s[i] === '}') break;
      return undefined;
    }
    return match < 0 ? undefined : seek(s, match, path, k + 1);
  }

  if (s[i] !== '[') return undefined;
  i++;
  for (let index = 0; ; index++) {
    i = skipTrivia(s, i);
    if (s[i] === ']') return undefined;
    if (index === seg) return seek(s, i, path, k + 1);
    const valueEnd = skipValue(s, i);
    if (valueEnd < 0) return undefined;
    i = skipTrivia(s, valueEnd);
    if (s[i] === ',') { i++; continue; }
    return undefined;
  }
}

function valueIs(s: string, at: number, expected: string | boolean): boolean {
  if (typeof expected === 'boolean') {
    const word = expected ? 'true' : 'false';
    return s.startsWith(word, at) && isDelimiter(s, at + word.length);
  }
  if (s[at] !== '"') return false;
  const end = skipString(s, at);
  if (end < 0) return false;
  try { return JSON.parse(s.slice(at, end)) === expected; } catch { return false; }
}

/** Whitespace and JSONC comments. */
function skipTrivia(s: string, from: number): number {
  let i = from;
  for (;;) {
    while (i < s.length) {
      const c = s.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i++;
      else break;
    }
    if (s[i] === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') i++;
      continue;
    }
    if (s[i] === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      i = end < 0 ? s.length : end + 2;
      continue;
    }
    return i;
  }
}

/** Index just past the string opening at `from`, or -1 when it never closes. */
function skipString(s: string, from: number): number {
  for (let i = from + 1; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') { i++; continue; }
    if (c === '"') return i + 1;
  }
  return -1;
}

/** Index just past the value starting at `from`, or -1 when it is malformed. */
function skipValue(s: string, from: number): number {
  const c = s[from];
  if (c === '"') return skipString(s, from);
  if (c === '{' || c === '[') {
    // Iterative, so a deeply nested value cannot exhaust the stack.
    let depth = 0;
    let i = from;
    while (i < s.length) {
      const ch = s[i];
      if (ch === '"') {
        const end = skipString(s, i);
        if (end < 0) return -1;
        i = end;
        continue;
      }
      if (ch === '/' && (s[i + 1] === '/' || s[i + 1] === '*')) {
        i = skipTrivia(s, i);
        continue;
      }
      if (ch === '{' || ch === '[') depth++;
      else if (ch === '}' || ch === ']') {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return -1;
  }
  let i = from;
  while (i < s.length && !isDelimiter(s, i)) i++;
  return i === from ? -1 : i;
}

function isDelimiter(s: string, i: number): boolean {
  if (i >= s.length) return true;
  const c = s[i];
  return c === ',' || c === '}' || c === ']' || c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '/';
}
